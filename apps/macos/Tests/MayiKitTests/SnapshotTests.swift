import SwiftUI
import Testing

@testable import MayiKit

/// Renders the main screens with sample data. Run with MAYI_SNAPSHOT_DIR set
/// to get PNGs; without it these only check that the views build.
@MainActor
@Suite struct SnapshotTests {
    let request = RequestInfo(
        command: "sh -c 'terraform apply -auto-approve && curl -s https://hooks.example.com/done'", site: nil,
        fields: [], cwd: "/Users/amine/Sources/infra", reason: "Apply the staging network change you asked for",
        agent: "claude-code", session: "ppid:48213", host: "Amines-Mac-mini", requester: "local", remote: false)
    let signIn = RequestInfo(
        command: "", site: "https://github.com", fields: ["username", "password", "totp"],
        cwd: "/Users/amine/Sources/release-notes", reason: "Open the billing page to download this month's invoice",
        agent: "claude-code", session: "ppid:48213", host: "build-vm", requester: "build-vm (3f9a1c2e)", remote: true)

    @Test func approval() async throws {
        let prompt = PromptInfo(
            runId: 1, request: request,
            secrets: [
                PromptSecret(name: "AWS_SECRET_ACCESS_KEY", level: 3, needsApproval: true),
                PromptSecret(name: "TF_TOKEN", level: 1, needsApproval: false),
            ])
        try await snapshot(ApprovalView(prompt: prompt, waiting: 1) { _ in }, name: "approval-dark")
        try await snapshot(ApprovalView(prompt: prompt, waiting: 1) { _ in }, name: "approval-light", dark: false)
    }

    @Test func signInApproval() async throws {
        let prompt = PromptInfo(
            runId: 2, request: signIn, secrets: [PromptSecret(name: "github", level: 3, needsApproval: true)])
        try await snapshot(ApprovalView(prompt: prompt) { _ in }, name: "sign-in-light", dark: false)
        try await snapshot(ApprovalView(prompt: prompt) { _ in }, name: "sign-in-dark")
        let notice = NoticeInfo(runId: 8, request: signIn, secrets: ["github"])
        try await snapshot(
            NoticeView(active: .init(notice: notice), onStop: {}, onDismiss: {}).padding(8), name: "sign-in-notice",
            dark: false)
    }

    @Test func loginEditor() async throws {
        var draft = SecretDraft()
        draft.login = true
        draft.name = "github"
        draft.sitesText = "github.com"
        draft.username = "amine"
        draft.password = "correct horse"
        draft.twoFactorKey = "JBSWY3DPEHPK3PXP"
        try await snapshot(
            SecretEditor(existing: nil, draft: draft, onSave: { _ in nil }, onCancel: {}), name: "login-editor",
            dark: false)
    }

    @Test func notices() async throws {
        let notice = NoticeInfo(runId: 7, request: request, secrets: ["GITHUB_TOKEN"])
        let stack = VStack(spacing: 8) {
            NoticeView(active: .init(notice: notice), onStop: {}, onDismiss: {})
            NoticeView(active: .init(notice: notice, ended: true, stopped: true), onStop: {}, onDismiss: {})
        }
        .padding(8)
        try await snapshot(stack, name: "notices-dark")
        try await snapshot(stack, name: "notices-light", dark: false)
    }

    @Test func editor() async throws {
        let stored = SecretRecord(
            name: "PROD_DB", level: 4, fields: ["password", "user"], allow: ["psql *", "pg_dump *"],
            maxGrantSecs: 300, version: 2, login: false, sites: [])
        try await snapshot(
            SecretEditor(
                existing: stored, error: "Changing the level re-encrypts the secret, so enter its values again.",
                onSave: { _ in nil }, onCancel: {}),
            name: "editor", dark: false)
    }

    @Test func pairing() async throws {
        try await snapshot(
            PairingSheet(
                token: "mayi1.Qm9ndXNUb2tlbkZvclNuYXBzaG90c09ubHlOb3RSZWFsQm9ndXNUb2tlbkZvclNuYXBzaG90c09ubHk",
                paired: nil, onClose: {}),
            name: "pairing", dark: false)
        try await snapshot(PairingSheet(token: nil, paired: "build-vm", onClose: {}), name: "paired")
    }

    @Test func welcome() async throws {
        let dir = try scratch()
        let welcome = WelcomeModel(
            paths: MayiPaths(home: dir.appendingPathComponent("w"), socket: "", port: 0, advertise: ["192.168.1.20"]),
            keys: TestKeys(), deviceName: "Mac mini"
        ) { _ in }
        welcome.start()
        defer { welcome.stop() }
        try await snapshot(WelcomeView(model: welcome), name: "welcome", dark: false)
        try await snapshot(WelcomeView(model: welcome), name: "welcome-dark")
    }

    @Test func enrolment() async throws {
        try await snapshot(
            EnrolmentSheet(
                token: "mayid1.Qm9ndXNUb2tlbkZvclNuYXBzaG90c09ubHlOb3RSZWFsQm9ndXNUb2tlbkZvclNuYXBzaG90c09ubHkAAAAAAAAAMTAuMC4wLjI",
                added: nil, onAddByCode: { _ in nil }, onClose: {}),
            name: "enrolment")
    }

    /// The real window gets the toolbar buttons the SwiftUI views ask for.
    /// Without them there would be no way to add a secret.
    @Test func mainWindowHasItsToolbar() async throws {
        let dir = try scratch()
        let model = AppModel(presence: FixedPresence())
        try model.start(
            keys: TestKeys(),
            paths: MayiPaths(
                home: dir.appendingPathComponent("home"), socket: dir.appendingPathComponent("s.sock").path),
            deviceName: "test")
        _ = model.saveSecret(name: "GITHUB_TOKEN", level: 2, values: ["value": "x"], allow: ["gh *"], maxGrantSecs: 900)
        _ = model.saveSecret(name: "PROD_DB", level: 4, values: ["value": "x"], allow: [], maxGrantSecs: 300)
        _ = NSApplication.shared
        let window = MainWindow.make(model: model)
        window.orderFrontRegardless()
        defer { window.close() }
        try await eventually { (window.toolbar?.items.count ?? 0) > 0 }
        let labels = window.toolbar?.items.map(\.label) ?? []
        #expect(labels.contains("Add Secret"), "toolbar items: \(labels)")
    }

    @Test func recoveryKey() async throws {
        try await snapshot(
            RecoveryKeySheet(key: "mayi-recovery1.22974e7c0b1d4f6a8e3c5d7f9a1b2c3d4e5f60718293a4b5c6d7e8f901234567") {},
            name: "recovery")
    }

    @Test func mainWindow() async throws {
        let dir = try scratch()
        let model = AppModel(presence: FixedPresence())
        try model.start(
            keys: TestKeys(),
            paths: MayiPaths(
                home: dir.appendingPathComponent("home"), socket: dir.appendingPathComponent("s.sock").path),
            deviceName: "test")
        _ = model.saveSecret(name: "GITHUB_TOKEN", level: 2, values: ["value": "x"], allow: ["gh *"], maxGrantSecs: 900)
        _ = model.saveSecret(name: "AWS_SECRET_ACCESS_KEY", level: 3, values: ["value": "x"], allow: [], maxGrantSecs: 900)
        _ = model.saveSecret(
            name: "PROD_DB", level: 4, values: ["user": "x", "password": "y"], allow: ["psql *"], maxGrantSecs: 300)
        _ = model.saveSecret(name: "NPM_TOKEN", level: 1, values: ["value": "x"], allow: [], maxGrantSecs: 900)
        _ = model.saveSecret(
            name: "github", level: 3, values: ["username": "amine", "password": "x", "totp": "JBSWY3DPEHPK3PXP"],
            allow: [], maxGrantSecs: 600, login: true, sites: ["github.com"])
        _ = try await mayi(
            ["run", "-s", "NPM_TOKEN", "-r", "Publish the release you tagged", "--", "true"],
            socket: model.socketPath!)
        // GITHUB_TOKEN expects `gh *`, so this command is raised to an approval.
        async let refused = mayi(
            ["run", "-s", "GITHUB_TOKEN", "-r", "Check the build", "--", "curl", "https://example.com"],
            socket: model.socketPath!)
        try await eventually { !model.pending.isEmpty }
        model.answer(model.pending[0].id, .deny)
        #expect(try await refused.status == 77)
        try await eventually { model.log.count == 3 }
        _ = NSApplication.shared
        for (section, dark) in [
            (MainView.Section.secrets, false), (.secrets, true), (.activity, false), (.devices, true),
        ] {
            let window = MainWindow.make(model: model, section: section)
            try await capture(window, name: "window-\(section.rawValue.lowercased())-\(dark ? "dark" : "light")", dark: dark)
            window.close()
        }
    }
}
