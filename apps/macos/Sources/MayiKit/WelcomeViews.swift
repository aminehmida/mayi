import AppKit
import SwiftUI

/// Setting up a Mac that has no vault yet: join the vault another device
/// holds, or start a new one. Nothing is created until the user chooses.
@MainActor
public final class WelcomeModel: ObservableObject {
    /// The code this Mac shows for a device with the vault to scan or paste.
    @Published public private(set) var code: String?
    /// What is happening, for the line under the code.
    @Published public private(set) var status = "Getting a code ready\u{2026}"
    @Published public private(set) var error: String?
    @Published public private(set) var busy = false
    @Published public var invitation = ""

    private let paths: MayiPaths
    private let keys: KeyStore
    private let deviceName: String
    /// Called once the vault exists, joined or created.
    private let onReady: (_ created: Bool) -> Void
    private var join: JoinInvitation?

    /// How long a code stays valid before a fresh one replaces it.
    public static let codeMinutes: UInt64 = 10

    public init(paths: MayiPaths, keys: KeyStore, deviceName: String, onReady: @escaping (_ created: Bool) -> Void) {
        self.paths = paths
        self.keys = keys
        self.deviceName = deviceName
        self.onReady = onReady
    }

    /// Shows a code and waits for a device with the vault to add this Mac.
    /// A fresh code replaces one that expired.
    public func start() {
        do {
            try FileManager.default.createDirectory(
                at: paths.home, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let join = try JoinInvitation.open(addresses: paths.advertise, ttlSecs: Self.codeMinutes * 60)
            self.join = join
            code = join.token()
            status = "Waiting for your other device\u{2026}"
            let (vault, name, keys) = (paths.vault.path, deviceName, keys)
            Task {
                do {
                    try await Task.detached { try join.wait(vaultPath: vault, deviceName: name, keys: keys) }.value
                    finish(created: false)
                } catch {
                    let reason = describe(error)
                    if join !== self.join || reason == "vault: cancelled" { return }
                    if reason != "vault: the code expired" { self.error = "Not joined: \(reason)" }
                    start()
                }
            }
        } catch {
            self.error = describe(error)
            status = "No code: this Mac could not open a port for your other device."
        }
    }

    /// Joins with an invitation from a device that holds the vault ("Add a
    /// Device" on another Mac shows one as text).
    public func joinWithInvitation() {
        let token = invitation.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty else { return }
        busy = true
        error = nil
        // Joining this way also creates the vault file, so the code stops.
        stop()
        let (vault, name, keys) = (paths.vault.path, deviceName, keys)
        Task {
            do {
                try await Task.detached { try joinVault(vaultPath: vault, deviceName: name, keys: keys, token: token) }.value
                finish(created: false)
            } catch {
                busy = false
                self.error = "Not joined: \(describe(error))"
                start()
            }
        }
    }

    public func createNew() {
        stop()
        finish(created: true)
    }

    public func stop() {
        join?.cancel()
        join = nil
    }

    private func finish(created: Bool) {
        stop()
        onReady(created)
    }
}

public struct WelcomeView: View {
    @ObservedObject var model: WelcomeModel
    @State private var copied = false
    @State private var confirmCreate = false

    public init(model: WelcomeModel) {
        self.model = model
    }

    public var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    HStack(alignment: .center, spacing: 14) {
                        AppIconView(size: 52)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("Set Up Mayi on This Mac").font(.title3.weight(.semibold))
                            Text("Join the vault you already have on another device, or start a new one.")
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .padding(.vertical, 4)
                }

                Section {
                    HStack(alignment: .top, spacing: 16) {
                        codeImage
                        VStack(alignment: .leading, spacing: 10) {
                            Text("On your phone, open Mayi, go to Devices, choose Add a device, and scan this code.")
                                .fixedSize(horizontal: false, vertical: true)
                            Text("From another Mac, choose Add a Device there and paste the code.")
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            Button(copied ? "Copied" : "Copy Code") {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(model.code ?? "", forType: .string)
                                copied = true
                            }
                            .disabled(model.code == nil)
                            HStack(spacing: 6) {
                                if model.code != nil && !model.busy { ProgressView().controlSize(.small) }
                                Text(model.status).font(.callout).foregroundStyle(.secondary)
                            }
                        }
                    }
                    .padding(.vertical, 4)
                } header: {
                    Text("Join Your Vault")
                } footer: {
                    Text("Your other device asks you to confirm, then sends this Mac a copy of every secret.")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                Section {
                    HStack {
                        TextField("Invitation", text: $model.invitation, prompt: Text("mayid1.\u{2026}"))
                            .labelsHidden()
                            .font(.system(.body, design: .monospaced))
                            .onSubmit(model.joinWithInvitation)
                        Button("Join", action: model.joinWithInvitation)
                            .disabled(model.invitation.trimmingCharacters(in: .whitespaces).isEmpty || model.busy)
                    }
                } header: {
                    Text("Or Use an Invitation")
                } footer: {
                    Text("A Mac that has your vault shows one under Devices, Add a Device, Copy as Text.")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                Section {
                    HStack {
                        Text("Start a new, empty vault here if this is your first device.")
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer()
                        Button("Create New Vault\u{2026}") { confirmCreate = true }
                            .disabled(model.busy)
                    }
                }
            }
            .formStyle(.grouped)

            if let error = model.error {
                Divider()
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 20)
                    .padding(.vertical, 10)
            }
        }
        .frame(width: 560)
        .fixedSize(horizontal: false, vertical: true)
        .confirmationDialog("Create a new vault on this Mac?", isPresented: $confirmCreate) {
            Button("Create New Vault", action: model.createNew)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("If your secrets are on your phone or another Mac, join that vault instead. Two vaults do not share anything.")
        }
    }

    @ViewBuilder private var codeImage: some View {
        if let code = model.code, let image = qrCode(code) {
            // A QR code must stay black on white to scan, in either appearance.
            Image(nsImage: image)
                .interpolation(.none)
                .resizable()
                .frame(width: 168, height: 168)
                .padding(8)
                .background(Color.white, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(.separator, lineWidth: 0.5))
        } else {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(.quaternary)
                .frame(width: 184, height: 184)
        }
    }
}
