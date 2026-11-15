import AppKit
import MayiKit

MainActor.assumeIsolated {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    // A menu-bar app: no Dock icon.
    app.setActivationPolicy(.accessory)
    app.run()
}
