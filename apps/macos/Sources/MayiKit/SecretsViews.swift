import AppKit
import SwiftUI

public struct SecretEditor: View {
    let existing: SecretRecord?
    /// Decrypts the stored values once the owner confirms. Without it, the
    /// editor cannot show them.
    let onReveal: (() async -> Result<RevealedSecret, DraftError>)?
    /// Show the values as soon as the editor opens.
    let revealOnOpen: Bool
    let onSave: (SecretDraft.Change) -> String?
    let onCancel: () -> Void
    @State var draft: SecretDraft
    @State var error: String?
    @State private var revealing = false
    /// A login's current two-factor code, and when it stops being valid.
    @State private var code: (value: String, until: Date)?

    public init(
        existing: SecretRecord?, draft: SecretDraft? = nil, error: String? = nil,
        onReveal: (() async -> Result<RevealedSecret, DraftError>)? = nil, revealOnOpen: Bool = false,
        onSave: @escaping (SecretDraft.Change) -> String?, onCancel: @escaping () -> Void
    ) {
        self.existing = existing
        self.onReveal = onReveal
        self.revealOnOpen = revealOnOpen
        self.onSave = onSave
        self.onCancel = onCancel
        _draft = State(initialValue: draft ?? existing.map(SecretDraft.init(editing:)) ?? SecretDraft())
        _error = State(initialValue: error)
    }

    private var shown: Bool { draft.shown != nil }

    private func reveal() async {
        guard let onReveal else { return }
        revealing = true
        error = nil
        switch await onReveal() {
        case .success(let revealed):
            draft.show(revealed)
            code = revealed.code.map { ($0, Date().addingTimeInterval(TimeInterval(revealed.codeValidSecs))) }
        case .failure(let problem):
            error = problem.message
        }
        revealing = false
    }

    /// Where the stored values are shown, or the button that shows them.
    @ViewBuilder private var showValues: some View {
        if existing != nil, onReveal != nil, !shown {
            Button {
                Task { await reveal() }
            } label: {
                Label(revealing ? "Waiting for You\u{2026}" : "Show Values", systemImage: "eye")
            }
            .disabled(revealing)
        }
    }

    /// A value field: hidden while typing a new one, readable once shown.
    @ViewBuilder private func valueField(_ title: String, _ text: Binding<String>, prompt: String?) -> some View {
        if shown {
            HStack {
                TextField(title, text: text, prompt: prompt.map { Text($0) })
                    .font(.system(.body, design: .monospaced))
                CopyButton(value: text.wrappedValue)
            }
        } else {
            SecureField(title, text: text, prompt: prompt.map { Text($0) })
        }
    }

    public var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    Picker("Type", selection: $draft.login) {
                        Label("Secret", systemImage: "key").tag(false)
                        Label("Website Login", systemImage: "globe").tag(true)
                    }
                    .disabled(existing != nil)
                    TextField("Name", text: $draft.name, prompt: Text(draft.login ? "github" : "GITHUB_TOKEN"))
                        .font(.system(.body, design: .monospaced))
                        .disabled(existing != nil)
                    Picker("Level", selection: $draft.level) {
                        ForEach(UInt8(1)...4, id: \.self) { level in
                            Label(LevelInfo.name(level), systemImage: LevelInfo.symbol(level)).tag(level)
                        }
                    }
                } footer: {
                    Text(
                        draft.login
                            ? "\(LevelInfo.detail(draft.level, login: true)) A login is only ever typed into its websites, never given to a command."
                            : LevelInfo.detail(draft.level)
                    )
                    .frame(maxWidth: .infinity, alignment: .leading)
                }

                if draft.login {
                    loginSections
                } else {
                    secretSections
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack(spacing: 10) {
                if let error {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.red)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel)
                    .keyboardShortcut(.cancelAction)
                Button(existing == nil ? (draft.login ? "Add Login" : "Add Secret") : "Save") {
                    switch draft.change(existing: existing) {
                    case .success(let change): error = onSave(change)
                    case .failure(let problem): error = problem.message
                    }
                }
                .keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
        }
        .frame(width: 500, height: 620)
        .task {
            if revealOnOpen { await reveal() }
        }
    }

    private var keep: String? { existing == nil || shown ? nil : "unchanged" }

    @ViewBuilder private var loginSections: some View {
        Section {
            TextEditor(text: $draft.sitesText)
                .font(.system(.body, design: .monospaced))
                .frame(height: 48)
        } header: {
            Text("Websites")
        } footer: {
            Text(
                "One per line, as the address bar shows it: github.com. *.example.com covers its subdomains. Mayi types this login into these sites only, and only over https."
            )
            .frame(maxWidth: .infinity, alignment: .leading)
        }

        Section {
            HStack {
                TextField("Username", text: $draft.username, prompt: Text(keep ?? "optional"))
                if shown { CopyButton(value: draft.username) }
            }
            valueField("Password", $draft.password, prompt: keep ?? "required")
            valueField("Two-Factor Key", $draft.twoFactorKey, prompt: keep ?? "optional")
            if let code {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let left = Int(code.until.timeIntervalSince(context.date).rounded(.up))
                    if left > 0 {
                        HStack {
                            Text("Code now")
                            Spacer()
                            Text(code.value).font(.system(.body, design: .monospaced))
                            Text("for \(left) s").foregroundStyle(.secondary).monospacedDigit()
                            CopyButton(value: code.value)
                        }
                    } else {
                        Button("Show the Next Code") { Task { await reveal() } }
                    }
                }
            }
            showValues
        } header: {
            Text("Sign-In")
        } footer: {
            Text(
                existing == nil
                    ? "The two-factor key is the setup key or otpauth:// link a site shows when you turn on an authenticator app. It stays on your devices: a page only ever gets the current code."
                    : shown
                        ? "Edit what you need and save. Copied values are cleared from the clipboard after a minute."
                        : "Leave all three empty to keep what is stored, or show them to read and edit them. Changing the level needs the password again."
            )
            .frame(maxWidth: .infinity, alignment: .leading)
        }

        Section {
            Stepper(value: $draft.maxGrantMinutes, in: 0...240, step: 5) {
                Text(
                    draft.maxGrantMinutes == 0
                        ? "Ask on every page" : "An approval lasts at most \(draft.maxGrantMinutes) minutes")
            }
        } header: {
            Text("Approvals")
        } footer: {
            Text("Allow Once also covers the next pages of the same sign-in, for two minutes.")
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder private var secretSections: some View {
                Section {
                    ForEach($draft.fields) { $field in
                        HStack {
                            TextField("Field", text: $field.name, prompt: Text("field"))
                                .labelsHidden()
                                .font(.system(.body, design: .monospaced))
                                .frame(width: 120)
                            valueField("Value", $field.value, prompt: existing == nil ? "value" : keep)
                                .labelsHidden()
                            Button {
                                draft.fields.removeAll { $0.id == field.id }
                            } label: {
                                Image(systemName: "minus.circle")
                            }
                            .buttonStyle(.borderless)
                            .disabled(draft.fields.count == 1)
                            .help("Remove this field")
                        }
                    }
                    Button("Add Field") { draft.fields.append(.init(name: "")) }
                        .buttonStyle(.borderless)
                    showValues
                } header: {
                    Text("Value")
                } footer: {
                    if existing != nil {
                        Text(
                            shown
                                ? "Edit what you need and save. Copied values are cleared from the clipboard after a minute."
                                : "Leave empty to keep what is stored, or show it to read and edit it. Changing the level needs the value again."
                        )
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }

                Section {
                    TextEditor(text: $draft.allowText)
                        .font(.system(.body, design: .monospaced))
                        .frame(height: 48)
                    Stepper(value: $draft.maxGrantMinutes, in: 0...240, step: 5) {
                        Text(
                            draft.maxGrantMinutes == 0
                                ? "Ask every time" : "An approval lasts at most \(draft.maxGrantMinutes) minutes")
                    }
                } header: {
                    Text("Expected Commands")
                } footer: {
                    Text(
                        "One per line; * matches anything. An expected command skips the prompt at level 3. Any other command is asked about, whatever the level."
                    )
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
    }
}

struct SecretRow: View {
    let secret: SecretRecord

    /// What the secret holds and which commands it is meant for, as a sentence.
    private var summary: String {
        if secret.login {
            let sites = "Signs in to " + secret.sites.joined(separator: ", ")
            return secret.fields.contains("totp") ? sites + ", with a two-factor code" : sites
        }
        var parts: [String] = []
        if secret.fields != ["value"] {
            parts.append("Holds " + secret.fields.joined(separator: ", "))
        }
        parts.append(
            secret.allow.isEmpty
                ? "Any command may ask for it" : "Expected with " + secret.allow.joined(separator: ", "))
        return parts.joined(separator: ". ")
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: secret.login ? "globe" : "key")
                .foregroundStyle(.secondary)
                .frame(width: 18)
                .accessibilityLabel(secret.login ? "Website login" : "Secret")
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(secret.name).font(.system(.body, design: .monospaced))
                    if secret.copies < 2 {
                        OneCopyDot()
                    }
                }
                Text(summary).font(.callout).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            LevelLabel(level: secret.level)
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
    }
}

/// Marks a secret that exists only on this Mac, so it is lost if the Mac is.
struct OneCopyDot: View {
    var body: some View {
        Circle()
            .fill(.orange)
            .frame(width: 8, height: 8)
            .help("Only on this Mac. It reaches your other devices when they next sync; add a device to keep a second copy.")
            .accessibilityLabel("Only on this Mac")
    }
}

/// Copies a value, marked so clipboard managers skip it, and clears it from
/// the clipboard after a minute unless something else was copied since.
struct CopyButton: View {
    let value: String

    var body: some View {
        Button {
            let board = NSPasteboard.general
            board.clearContents()
            board.setString(value, forType: .string)
            board.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
            let copied = board.changeCount
            DispatchQueue.main.asyncAfter(deadline: .now() + 60) {
                if board.changeCount == copied { board.clearContents() }
            }
        } label: {
            Image(systemName: "doc.on.doc")
        }
        .buttonStyle(.borderless)
        .disabled(value.isEmpty)
        .help("Copy; cleared from the clipboard after a minute")
    }
}

public struct SecretsView: View {
    @ObservedObject var model: AppModel
    @State private var selection: String?
    @State private var editor: EditorTarget?
    @State private var confirmDelete: String?
    @State private var error: String?

    private enum EditorTarget: Identifiable {
        case new
        case edit(SecretRecord)
        /// Edit, showing the values first.
        case show(SecretRecord)

        var id: String {
            switch self {
            case .new: return ""
            case .edit(let secret): return "edit:" + secret.name
            case .show(let secret): return "show:" + secret.name
            }
        }

        var existing: SecretRecord? {
            switch self {
            case .new: return nil
            case .edit(let secret), .show(let secret): return secret
            }
        }

        var revealsAtOnce: Bool {
            if case .show = self { return true }
            return false
        }
    }

    public init(model: AppModel) {
        self.model = model
    }

    private func secret(_ name: String?) -> SecretRecord? {
        model.secrets.first { $0.name == name }
    }

    public var body: some View {
        List(selection: $selection) {
            ForEach(model.secrets, id: \.name) { secret in
                SecretRow(secret: secret).tag(secret.name)
            }
        }
        .listStyle(.inset)
        .contextMenu(forSelectionType: String.self) { names in
            if let secret = secret(names.first) {
                Button("Show Values\u{2026}") { editor = .show(secret) }
                Button("Edit\u{2026}") { editor = .edit(secret) }
                Button("Delete\u{2026}", role: .destructive) { confirmDelete = secret.name }
            }
        } primaryAction: { names in
            if let secret = secret(names.first) { editor = .edit(secret) }
        }
        .overlay {
            if model.secrets.isEmpty {
                ContentUnavailableView {
                    Label("No Secrets", systemImage: "key")
                } description: {
                    Text("Add an API key, a token or a website login. An agent then uses it by name, with mayi run or mayi fill, and never sees the value.")
                } actions: {
                    Button("Add Secret") { editor = .new }
                }
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) { StatusBar(message: error, isError: true) }
        .navigationTitle("Secrets")
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    if let secret = secret(selection) { editor = .show(secret) }
                } label: {
                    Label("Show Values", systemImage: "eye")
                }
                .disabled(secret(selection) == nil)
                .help("Show the selected secret's values, after you confirm")
                Button {
                    if let secret = secret(selection) { editor = .edit(secret) }
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                .disabled(secret(selection) == nil)
                .help("Edit the selected secret")
                Button {
                    confirmDelete = selection
                } label: {
                    Label("Delete", systemImage: "trash")
                }
                .disabled(secret(selection) == nil)
                .help("Delete the selected secret")
                Button {
                    editor = .new
                } label: {
                    Label("Add Secret", systemImage: "plus")
                }
                .help("Add a secret")
            }
        }
        .sheet(item: $editor) { target in
            SecretEditor(
                existing: target.existing,
                onReveal: target.existing.map { secret in { await model.revealSecret(secret) } },
                revealOnOpen: target.revealsAtOnce,
                onSave: { change in
                    let problem = apply(change)
                    if problem == nil { editor = nil }
                    return problem
                },
                onCancel: { editor = nil })
        }
        .confirmationDialog(
            "Delete \(confirmDelete ?? "")?", isPresented: .constant(confirmDelete != nil), presenting: confirmDelete
        ) { name in
            Button("Delete", role: .destructive) {
                error = model.deleteSecret(name: name)
                selection = nil
                confirmDelete = nil
            }
            Button("Cancel", role: .cancel) { confirmDelete = nil }
        } message: { _ in
            Text("Agents will no longer be able to use it. This cannot be undone from the app.")
        }
    }

    private func apply(_ change: SecretDraft.Change) -> String? {
        switch change {
        case .put(let name, let level, let values, let allow, let maxGrantSecs, let login, let sites):
            return model.saveSecret(
                name: name, level: level, values: values, allow: allow, maxGrantSecs: maxGrantSecs, login: login,
                sites: sites)
        case .rules(let name, let allow, let maxGrantSecs, let sites):
            return model.updateRules(name: name, allow: allow, maxGrantSecs: maxGrantSecs, sites: sites)
        }
    }
}

// MARK: Activity

public struct ActivityView: View {
    @ObservedObject var model: AppModel

    public init(model: AppModel) {
        self.model = model
    }

    private struct Day: Identifiable {
        let id: Date
        var entries: [AuditRecord]
    }

    /// Newest first, split where the calendar day changes.
    private var days: [Day] {
        var days: [Day] = []
        for entry in model.log.reversed() {
            let day = Calendar.current.startOfDay(for: Date(timeIntervalSince1970: Double(entry.tsMs) / 1000))
            if days.last?.id == day {
                days[days.count - 1].entries.append(entry)
            } else {
                days.append(Day(id: day, entries: [entry]))
            }
        }
        return days
    }

    private static let dayFormat: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .full
        formatter.timeStyle = .none
        formatter.doesRelativeDateFormatting = true
        return formatter
    }()

    public var body: some View {
        List {
            ForEach(days) { day in
                Section(Self.dayFormat.string(from: day.id)) {
                    ForEach(Array(day.entries.enumerated()), id: \.offset) { _, entry in
                        ActivityRow(entry: entry)
                    }
                }
            }
        }
        .listStyle(.inset)
        .overlay {
            if model.log.isEmpty {
                ContentUnavailableView(
                    "No Activity", systemImage: "clock",
                    description: Text("Every request is recorded here with its command or website and the reason given, whether it was allowed or not."))
            }
        }
        .navigationTitle("Activity")
    }
}

struct ActivityRow: View {
    let entry: AuditRecord

    private static let time: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .medium
        return formatter
    }()

    private var released: Bool { entry.outcome == "released" }

    /// How a secret came to be released, in the user's terms.
    private static func how(_ via: String) -> String {
        switch via {
        case "level": return "without asking"
        case "allowlist": return "as an expected command"
        case "grant": return "under an earlier approval"
        case "approval": return "with your approval"
        case "biometric": return "after you confirmed it"
        default: return via
        }
    }

    private var names: String { entry.secrets.map(\.name).joined(separator: ", ") }

    private var signIn: Bool { !entry.site.isEmpty }

    private var title: String {
        switch entry.event {
        case "request" where released && signIn:
            let ways = Set(entry.secrets.map { Self.how($0.via) })
            return "Typed \(names) into \(host(entry.site))" + (ways.count == 1 ? " \(ways.first!)" : "")
        case "request" where released:
            let ways = Set(entry.secrets.map { Self.how($0.via) })
            return "Released \(names)" + (ways.count == 1 ? " \(ways.first!)" : "")
        case "request":
            return names.isEmpty ? "Request refused" : "Refused \(names)"
        case "stop":
            return signIn ? "Sign-in stopped by you" : "Command stopped by you"
        case "view":
            return "You viewed \(names) on this Mac"
        default:
            // A sign-in's "command" is the typing; its exit says whether that worked.
            if signIn {
                return entry.outcome == "exit 0" ? "Sign-in submitted" : "Sign-in not completed"
            }
            return "Command finished" + (entry.outcome.hasPrefix("exit ") ? ", \(entry.outcome)" : "")
        }
    }

    /// Why a request was refused, as a sentence.
    private var refusal: String? {
        guard entry.event == "request", !released else { return nil }
        let why = entry.outcome.hasPrefix("denied: ") ? String(entry.outcome.dropFirst(8)) : entry.outcome
        return why.prefix(1).uppercased() + why.dropFirst() + "."
    }

    private var symbol: String {
        switch entry.event {
        case "request": return released ? "key" : "xmark.circle"
        case "stop": return "stop.circle"
        case "view": return "eye"
        default: return "checkmark"
        }
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: symbol)
                .foregroundStyle(
                    (entry.event == "request" && released) || entry.event == "view"
                        ? AnyShapeStyle(.primary) : entry.event == "exit" ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.red))
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .foregroundStyle(entry.event == "exit" ? .secondary : .primary)
                if let refusal {
                    Text(refusal).font(.callout).foregroundStyle(.red)
                }
                if entry.event == "request" {
                    Text(signIn ? entry.site : entry.command)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .textSelection(.enabled)
                    Text("Reason given: \u{201C}\(entry.reason)\u{201D}")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                    Text("\(entry.agent), \(entry.remote ? "from \(entry.requester)" : "on this Mac")")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
            Spacer()
            Text(Self.time.string(from: Date(timeIntervalSince1970: Double(entry.tsMs) / 1000)))
                .font(.callout.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, entry.event == "request" ? 4 : 1)
    }
}

// MARK: Main window

public struct MainView: View {
    @ObservedObject var model: AppModel
    @State private var section: Section?
    /// Told which section is showing, so the window can take its name.
    private let onSection: (Section) -> Void

    public enum Section: String, CaseIterable, Identifiable {
        case secrets = "Secrets"
        case machines = "Machines"
        case devices = "Devices"
        case activity = "Activity"

        public var id: String { rawValue }

        var symbol: String {
            switch self {
            case .secrets: return "key"
            case .machines: return "server.rack"
            case .devices: return "laptopcomputer.and.iphone"
            case .activity: return "clock"
            }
        }
    }

    public init(model: AppModel, section: Section = .secrets, onSection: @escaping (Section) -> Void = { _ in }) {
        self.model = model
        self.onSection = onSection
        _section = State(initialValue: section)
    }

    private func count(_ section: Section) -> Int {
        switch section {
        case .secrets: return model.secrets.count
        case .machines: return model.machines.filter { !$0.revoked }.count
        case .devices: return model.devices.filter { !$0.removed && !$0.recovery }.count
        case .activity: return 0
        }
    }

    public var body: some View {
        NavigationSplitView {
            List(Section.allCases, selection: $section) { item in
                Label(item.rawValue, systemImage: item.symbol)
                    .badge(count(item))
                    .tag(item)
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 170, ideal: 190, max: 240)
        } detail: {
            switch section ?? .secrets {
            case .secrets: SecretsView(model: model)
            case .machines: MachinesView(model: model)
            case .devices: DevicesView(model: model)
            case .activity: ActivityView(model: model)
            }
        }
        .frame(minWidth: 720, minHeight: 440)
        .onAppear {
            model.refresh()
            onSection(section ?? .secrets)
        }
        .onChange(of: section) { _, new in onSection(new ?? .secrets) }
    }
}
