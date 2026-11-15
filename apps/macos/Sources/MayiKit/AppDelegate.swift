import AppKit
import Combine
import SwiftUI

/// A floating panel that does not take keyboard focus from whatever the user
/// is typing in, so a keystroke meant for another app cannot answer a prompt.
private func floatingPanel(titled: Bool) -> NSPanel {
    let panel = NSPanel(
        contentRect: .zero,
        styleMask: titled
            ? [.titled, .nonactivatingPanel, .fullSizeContentView] : [.borderless, .nonactivatingPanel],
        backing: .buffered, defer: false)
    panel.titlebarAppearsTransparent = true
    panel.titleVisibility = .hidden
    panel.isMovableByWindowBackground = true
    panel.level = .floating
    panel.isFloatingPanel = true
    panel.hidesOnDeactivate = false
    panel.becomesKeyOnlyIfNeeded = true
    panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
    panel.isReleasedWhenClosed = false
    return panel
}

/// The management window: a standard Mac window with a sidebar and a
/// unified toolbar, its title and toolbar items supplied by the SwiftUI views.
@MainActor
public enum MainWindow {
    public static func make(model: AppModel, section: MainView.Section = .secrets) -> NSWindow {
        let window = NSWindow(
            contentRect: .zero, styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered, defer: false)
        // The toolbar buttons come from the SwiftUI views; the title is set
        // by hand, because that part of the bridge does not reach a window
        // made in AppKit.
        let controller = NSHostingController(
            rootView: MainView(model: model, section: section) { [weak window] shown in
                window?.title = shown.rawValue
            })
        controller.sceneBridgingOptions = [.toolbars]
        window.contentViewController = controller
        window.toolbarStyle = .unified
        window.title = section.rawValue
        window.isReleasedWhenClosed = false
        window.setContentSize(NSSize(width: 820, height: 520))
        window.center()
        return window
    }
}

@MainActor
public final class AppDelegate: NSObject, NSApplicationDelegate {
    public let model = AppModel()
    private var statusItem: NSStatusItem?
    private var mainWindow: NSWindow?
    private var approvalPanel: NSPanel?
    private var shownApproval: UUID?
    private var noticePanel: NSPanel?
    private var subscriptions = Set<AnyCancellable>()

    public func applicationDidFinishLaunching(_ notification: Notification) {
        let paths = MayiPaths.fromEnvironment()
        do {
            guard SecureEnclaveKeys.isAvailable else {
                throw MayiError.Failed(detail: "This Mac has no Secure Enclave, so it cannot be a vault device.")
            }
            let keys = try SecureEnclaveKeys.loadOrCreate(directory: paths.keys)
            try model.start(
                keys: keys, paths: paths, deviceName: Host.current().localizedName ?? "Mac")
        } catch {
            NSApp.activate(ignoringOtherApps: true)
            if recover(paths: paths, after: error) { return applicationDidFinishLaunching(notification) }
            let alert = NSAlert()
            alert.messageText = "Mayi could not start"
            alert.informativeText = describe(error)
            alert.runModal()
            NSApp.terminate(nil)
            return
        }
        installStatusItem(socket: paths.socket)
        model.$pending
            .receive(on: DispatchQueue.main)
            .sink { [weak self] pending in self?.showApproval(pending) }
            .store(in: &subscriptions)
        model.$notices
            .receive(on: DispatchQueue.main)
            .sink { [weak self] notices in self?.showNotices(isEmpty: notices.isEmpty) }
            .store(in: &subscriptions)
    }

    /// When the vault exists but this Mac's keys no longer open it (its
    /// fingerprints changed, or the files came from a backup), offers to
    /// restore access with the recovery key. Returns whether to try again.
    private func recover(paths: MayiPaths, after error: Error) -> Bool {
        guard FileManager.default.fileExists(atPath: paths.vault.path),
            describe(error).contains("not enrolled") || describe(error).contains("decryption failed")
        else { return false }
        let alert = NSAlert()
        alert.messageText = "This Mac can no longer open your vault"
        alert.informativeText =
            "Its keys were lost or replaced. Enter your recovery key to restore access, or quit and sync from another device."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 24))
        field.placeholderString = "mayi-recovery1.…"
        alert.accessoryView = field
        alert.addButton(withTitle: "Restore")
        alert.addButton(withTitle: "Quit")
        guard alert.runModal() == .alertFirstButtonReturn else { return false }
        do {
            let keys = try SecureEnclaveKeys.loadOrCreate(directory: paths.keys)
            try recoverVault(
                vaultPath: paths.vault.path, deviceName: Host.current().localizedName ?? "Mac", keys: keys,
                recoveryKey: field.stringValue)
            return true
        } catch {
            let failed = NSAlert()
            failed.messageText = "The recovery key did not work"
            failed.informativeText = describe(error)
            failed.runModal()
            return false
        }
    }

    private func installStatusItem(socket: String) {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = MayiGlyph.templateImage()
        item.button?.setAccessibilityLabel("Mayi")
        let menu = NSMenu()
        menu.addItem(withTitle: "Secrets and Activity…", action: #selector(openMainWindow), keyEquivalent: ",")
            .target = self
        menu.addItem(.separator())
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let shown = socket.hasPrefix(home) ? "~" + socket.dropFirst(home.count) : socket
        menu.addItem(withTitle: "Serving \(shown)", action: nil, keyEquivalent: "")
        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit Mayi", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        item.menu = menu
        statusItem = item
    }

    @objc public func openMainWindow() {
        if mainWindow == nil {
            mainWindow = MainWindow.make(model: model)
        }
        model.refresh()
        NSApp.activate(ignoringOtherApps: true)
        mainWindow?.makeKeyAndOrderFront(nil)
    }

    /// Shows the oldest pending approval; the rest wait their turn.
    private func showApproval(_ pending: [AppModel.PendingApproval]) {
        guard let first = pending.first else {
            approvalPanel?.orderOut(nil)
            shownApproval = nil
            return
        }
        if shownApproval == first.id { return }
        shownApproval = first.id
        let panel = approvalPanel ?? floatingPanel(titled: true)
        approvalPanel = panel
        panel.title = "Mayi"
        let view = ApprovalView(prompt: first.prompt, waiting: pending.count - 1) { [weak self] choice in
            self?.model.answer(first.id, choice)
        }
        let hosting = NSHostingView(rootView: view)
        panel.contentView = hosting
        panel.setContentSize(hosting.fittingSize)
        panel.center()
        panel.orderFrontRegardless()
        NSSound.beep()
    }

    private func showNotices(isEmpty: Bool) {
        if isEmpty {
            noticePanel?.orderOut(nil)
            return
        }
        let panel = noticePanel ?? {
            let panel = floatingPanel(titled: false)
            panel.backgroundColor = .clear
            panel.isOpaque = false
            panel.hasShadow = true
            panel.contentView = NSHostingView(rootView: NoticeStack(model: model))
            return panel
        }()
        noticePanel = panel
        guard let hosting = panel.contentView, let screen = NSScreen.main else { return }
        hosting.layoutSubtreeIfNeeded()
        let size = hosting.fittingSize
        let visible = screen.visibleFrame
        panel.setFrame(
            NSRect(x: visible.maxX - size.width - 12, y: visible.maxY - size.height - 12, width: size.width, height: size.height),
            display: true)
        panel.orderFrontRegardless()
    }
}
