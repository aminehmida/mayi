import AppKit
import CoreImage
import SwiftUI

public struct SecretEditor: View {
    let existing: SecretRecord?
    /// Decrypts the stored values once the owner confirms. Without it, the
    /// editor cannot show them.
    let onReveal: (() async -> Result<RevealedSecret, DraftError>)?
    /// Show the values as soon as the editor opens.
    let revealOnOpen: Bool
    /// Load the values when the editor opens, hidden behind their eyes: set
    /// when that asks nothing (Mayi is unlocked, the level is below 4).
    let loadsAtOnce: Bool
    /// The folders in use, offered in the folder field.
    let folders: [String]
    /// Drops the note that this secret should be rotated; returns an error.
    let onDismissRotation: (() -> String?)?
    @State private var rotationDismissed = false
    let onSave: (SecretDraft.Change) async -> String?
    let onCancel: () -> Void
    /// When adding: AWS Sign-In was picked as the type.
    let onPickAws: (() -> Void)?
    @State var draft: SecretDraft
    @State var error: String?
    @State private var revealing = false

    public init(
        existing: SecretRecord?, draft: SecretDraft? = nil, error: String? = nil,
        onReveal: (() async -> Result<RevealedSecret, DraftError>)? = nil, revealOnOpen: Bool = false,
        loadsAtOnce: Bool = false, folders: [String] = [], onDismissRotation: (() -> String?)? = nil,
        onSave: @escaping (SecretDraft.Change) async -> String?, onCancel: @escaping () -> Void,
        onPickAws: (() -> Void)? = nil
    ) {
        self.onPickAws = onPickAws
        self.existing = existing
        self.onReveal = onReveal
        self.revealOnOpen = revealOnOpen
        self.loadsAtOnce = loadsAtOnce
        self.folders = folders
        self.onDismissRotation = onDismissRotation
        self.onSave = onSave
        self.onCancel = onCancel
        _draft = State(initialValue: draft ?? existing.map(SecretDraft.init(editing:)) ?? SecretDraft())
        _error = State(initialValue: error)
    }

    private var shown: Bool { draft.shown != nil }
    private static let rotationSection = "rotation"

    /// Loads the stored values into the draft. Returns whether it did.
    @discardableResult
    private func reveal() async -> Bool {
        guard let onReveal, !revealing else { return shown }
        revealing = true
        error = nil
        defer { revealing = false }
        switch await onReveal() {
        case .success(let revealed):
            draft.show(revealed)
            return true
        case .failure(let problem):
            error = problem.message
            return false
        }
    }

    /// The eye's first press loads the stored values, when they are not yet.
    private var loadFirst: (() async -> Bool)? {
        existing != nil && !shown && onReveal != nil ? { await reveal() } : nil
    }

    /// A value field, hidden behind an eye that shows the current value (or
    /// what was typed), with a copy button once the stored value is loaded.
    @ViewBuilder private func valueField(
        _ title: String, _ text: Binding<String>, prompt: String?, editable: Bool = true
    ) -> some View {
        HStack {
            PeekField(
                title: title, text: text, prompt: prompt, startVisible: revealOnOpen, editable: editable,
                onFirstPeek: loadFirst)
            if shown { CopyButton(value: text.wrappedValue) }
        }
    }

    public var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                Form {
                    Section {
                        AddKindPicker(
                            kind: Binding(
                                get: { draft.login ? .login : .secret },
                                set: { kind in
                                    if kind == .aws { onPickAws?() } else { draft.login = kind == .login }
                                }),
                            offersAws: existing == nil && onPickAws != nil
                        )
                        .disabled(existing != nil)
                        TextField("Name", text: $draft.name, prompt: Text(draft.login ? "github" : "GITHUB_TOKEN"))
                            .font(.system(.body, design: .monospaced))
                            .disabled(existing != nil)
                        Picker("Level", selection: $draft.level) {
                            ForEach(UInt8(1)...4, id: \.self) { level in
                                Label(LevelInfo.name(level), systemImage: LevelInfo.symbol(level)).tag(level)
                            }
                        }
                        HStack {
                            TextField("Folder", text: $draft.folderText, prompt: Text("none"))
                            Menu {
                                ForEach(folders, id: \.self) { folder in
                                    Button(folder) { draft.folderText = folder }
                                }
                                if !draft.folderText.isEmpty {
                                    Divider()
                                    Button("No Folder") { draft.folderText = "" }
                                }
                            } label: {
                                Image(systemName: "folder")
                            }
                            .menuStyle(.borderlessButton)
                            .fixedSize()
                            .disabled(folders.isEmpty && draft.folderText.isEmpty)
                            .help("Choose a folder in use")
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
                    if let existing, !existing.rotate.isEmpty, !rotationDismissed {
                        Section {
                            VStack(alignment: .leading, spacing: 8) {
                                Label("Replace this value", systemImage: "exclamationmark.triangle.fill")
                                    .font(.headline)
                                    .symbolRenderingMode(.multicolor)
                                Text(rotationAdvice(existing.rotate))
                                    .fixedSize(horizontal: false, vertical: true)
                                HStack {
                                    Spacer()
                                    Button("Dismiss") {
                                        if let problem = onDismissRotation?() {
                                            error = problem
                                        } else {
                                            rotationDismissed = true
                                        }
                                    }
                                    .help("You checked, and this value needs no replacing")
                                }
                            }
                            .padding(.vertical, 4)
                        }
                        .id(Self.rotationSection)
                    }
                }
                .formStyle(.grouped)
                .onAppear {
                    // The note sits at the bottom; bring it into view.
                    if existing?.rotate.isEmpty == false { proxy.scrollTo(Self.rotationSection, anchor: .bottom) }
                }
            }

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
                    case .success(let change): Task { error = await onSave(change) }
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
            if revealOnOpen || loadsAtOnce { await reveal() }
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
            // A stored login changes only once its values are loaded, so that
            // what is not retyped is kept.
            let locked = existing != nil && !shown
            HStack {
                TextField("Username", text: $draft.username, prompt: Text(locked ? "unchanged" : "optional"))
                    .disabled(locked)
                if shown { CopyButton(value: draft.username) }
            }
            valueField("Password", $draft.password, prompt: locked ? "unchanged" : "required", editable: !locked)
            if let key = draft.effectiveTwoFactorKey {
                TwoFactorCodeRow(key: key)
            }
            if !locked {
                HStack {
                    PeekField(
                        title: draft.shown?["totp"] == nil ? "Two-Factor Key" : "New Two-Factor Key",
                        text: $draft.twoFactorKey,
                        prompt: draft.shown?["totp"] != nil && !draft.removeTwoFactor ? "unchanged" : "optional")
                    Button {
                        if let text = qrCode(on: .general) {
                            draft.twoFactorKey = text
                            error = nil
                        } else {
                            error = "No QR code on the clipboard. Press Control-Shift-Command-4, select the QR code, then paste it."
                        }
                    } label: {
                        Image(systemName: "qrcode.viewfinder")
                    }
                    .buttonStyle(.borderless)
                    .help("Paste a QR code you copied: press Control-Shift-Command-4 and select it")
                }
                if draft.shown?["totp"] != nil, !draft.removeTwoFactor, draft.twoFactorKey.isEmpty {
                    Button("Remove Two-Factor Key", role: .destructive) { draft.removeTwoFactor = true }
                        .buttonStyle(.borderless)
                }
            }
        } header: {
            Text("Sign-In")
        } footer: {
            Text(
                existing == nil
                    ? "The two-factor key is the setup key or otpauth:// link a site shows when you turn on an authenticator app; or copy its QR code and paste it with the QR button. It stays on your devices: a page only ever gets the current code."
                    : shown
                        ? "The code is what the site asks for now; the key behind it is never shown. To replace the key, type or paste a new one, or paste its QR code. Copied values are cleared from the clipboard after a minute."
                        : revealing
                            ? "Waiting for you to confirm\u{2026}"
                            : "Press the eye to see the current values and change them. Changing the level needs them too."
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
                } header: {
                    Text("Value")
                } footer: {
                    if existing != nil {
                        Text(
                            shown
                                ? "Edit what you need and save. Copied values are cleared from the clipboard after a minute."
                                : "Press the eye to see the current value, or type a new one; empty keeps it. Changing the level needs the value again."
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
    /// Opens the secret, from its rotation warning.
    var onOpen: () -> Void = {}

    /// What the secret holds and which commands it is meant for, as a sentence.
    private var summary: String {
        if let aws = secret.aws {
            let host = URL(string: aws.startUrl)?.host ?? aws.startUrl
            let roles = aws.profiles.map { "\($0.name) \($0.level)" }.joined(separator: ", ")
            return "AWS sign-in to \(host). " + (aws.profiles.isEmpty ? "No profiles" : "Profiles: " + roles)
        }
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
            Group {
                if secret.aws != nil {
                    AwsLogo()
                } else {
                    Image(systemName: secret.login ? "globe" : "key")
                        .foregroundStyle(.secondary)
                        .accessibilityLabel(secret.login ? "Website login" : "Secret")
                }
            }
            .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    if !secret.rotate.isEmpty {
                        Button(action: onOpen) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .symbolRenderingMode(.multicolor)
                        }
                        .buttonStyle(.borderless)
                        .help("May be known to \(rotationSummary(secret.rotate)). Open it to see what to do.")
                        .accessibilityLabel("Needs replacing")
                    }
                    Text(secret.name).font(.system(.body, design: .monospaced))
                    if secret.copies < 2 {
                        OneCopyDot()
                    }
                    if secret.aws?.cliHasSignIn == true {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .symbolRenderingMode(.multicolor)
                            .help("The AWS CLI saved a sign-in to this portal again: open it to remove it")
                    }
                }
                Text(summary).font(.callout).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if let aws = secret.aws {
                Text(aws.profiles.count == 1 ? "1 profile" : "\(aws.profiles.count) profiles")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                LevelLabel(level: secret.level)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

/// The code a two-factor key gives now, kept current, with a copy button.
struct TwoFactorCodeRow: View {
    let key: String

    /// "123456" as "123 456", as authenticator apps show it.
    static func grouped(_ code: String) -> String {
        guard code.count > 4 else { return code }
        let half = code.index(code.startIndex, offsetBy: code.count / 2)
        return code[..<half] + " " + code[half...]
    }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            if let current = try? twoFactorCode(key: key) {
                HStack {
                    Text("Two-Factor Code")
                    Spacer()
                    Text(Self.grouped(current.code)).font(.system(.title3, design: .monospaced))
                    Text("\(current.validSecs) s").foregroundStyle(.secondary).monospacedDigit()
                    CopyButton(value: current.code)
                }
            } else {
                Text("Not a two-factor key").foregroundStyle(.secondary)
            }
        }
    }
}

/// The text of a QR code in an image on `pasteboard`, if there is one.
func qrCode(on pasteboard: NSPasteboard) -> String? {
    guard let image = NSImage(pasteboard: pasteboard), let data = image.tiffRepresentation,
        let picture = CIImage(data: data)
    else { return nil }
    let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
    return detector?.features(in: picture).compactMap { ($0 as? CIQRCodeFeature)?.messageString }.first
}

/// A hidden field with an eye button that shows what was typed into it.
struct PeekField: View {
    let title: String
    @Binding var text: String
    let prompt: String?
    let editable: Bool
    /// Loads the stored value before the eye first shows it; nil when there
    /// is nothing to load. Returns whether it loaded.
    let onFirstPeek: (() async -> Bool)?
    @State private var visible: Bool

    init(
        title: String, text: Binding<String>, prompt: String?, startVisible: Bool = false, editable: Bool = true,
        onFirstPeek: (() async -> Bool)? = nil
    ) {
        self.title = title
        _text = text
        self.prompt = prompt
        self.editable = editable
        self.onFirstPeek = onFirstPeek
        _visible = State(initialValue: startVisible)
    }

    var body: some View {
        HStack {
            Group {
                if visible {
                    TextField(title, text: $text, prompt: prompt.map { Text($0) })
                        .font(.system(.body, design: .monospaced))
                } else {
                    SecureField(title, text: $text, prompt: prompt.map { Text($0) })
                }
            }
            .disabled(!editable)
            Button {
                if !visible, let onFirstPeek {
                    Task { if await onFirstPeek() { visible = true } }
                } else {
                    visible.toggle()
                }
            } label: {
                Image(systemName: visible ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .help(visible ? "Hide" : onFirstPeek != nil ? "Show the current value" : "Show")
            .accessibilityLabel(visible ? "Hide" : "Show")
        }
    }
}

private let noteDate: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateStyle = .medium
    formatter.timeStyle = .none
    return formatter
}()

/// "today", "yesterday" or "on 3 Nov 2026", for a sentence.
private func noteWhen(_ atMs: UInt64) -> String {
    let date = Date(timeIntervalSince1970: Double(atMs) / 1000)
    if Calendar.current.isDateInToday(date) { return "today" }
    if Calendar.current.isDateInYesterday(date) { return "yesterday" }
    return "on " + noteDate.string(from: date)
}

/// "Mac mini (test), revoked today" for each note.
func rotationSummary(_ notes: [RotateNoteRecord]) -> String {
    notes.map { "\($0.who), \($0.why) \(noteWhen($0.atMs))" }.joined(separator: "; ")
}

/// What to do about a secret that may be known to a revoked machine or a removed device.
func rotationAdvice(_ notes: [RotateNoteRecord]) -> String {
    let events = notes.map { "\($0.who) was \($0.why) \(noteWhen($0.atMs))" }
    let all = events.count == 1
        ? events[0] + ", and may still have this value."
        : events.joined(separator: ". ") + ". They may still have this value."
    return "\(all) Replace it where it was issued, for example with a new token from the service, then save the "
        + "new value here: that clears this note."
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
    /// Only the secrets in this folder, when set.
    let folder: String?
    @State private var query = ""
    @State private var selection: String?
    @State private var editor: EditorTarget?
    @State private var aws: AwsTarget?
    @State private var confirmDelete: String?
    @State private var error: String?

    private enum AwsTarget: Identifiable {
        case edit(SecretRecord)

        var id: String {
            switch self {
            case .edit(let secret): return secret.name
            }
        }
    }

    /// Opens a secret where it is edited: an AWS sign-in has its own editor.
    private func open(_ secret: SecretRecord, showing: Bool = false) {
        if secret.aws != nil {
            aws = .edit(secret)
        } else {
            editor = showing ? .show(secret) : .edit(secret)
        }
    }

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

    public init(model: AppModel, folder: String? = nil) {
        self.model = model
        self.folder = folder
    }

    private func secret(_ name: String?) -> SecretRecord? {
        model.secrets.first { $0.name == name }
    }

    /// The secrets in view: this folder's, matching the search by name,
    /// folder, website or field.
    private var shown: [SecretRecord] {
        let words = query.lowercased().split(separator: " ").map(String.init)
        return model.secrets.filter { secret in
            guard folder == nil || secret.folder == folder else { return false }
            let profiles = secret.aws.map { [$0.startUrl] + $0.profiles.flatMap { [$0.name, $0.role, $0.accountName] } } ?? []
            let text = ([secret.name, secret.folder ?? ""] + secret.sites + secret.fields + profiles)
                .joined(separator: " ").lowercased()
            return words.allSatisfy { text.contains($0) }
        }
    }

    public var body: some View {
        List(selection: $selection) {
            ForEach(shown, id: \.name) { secret in
                SecretRow(secret: secret, onOpen: { open(secret) }).tag(secret.name)
            }
        }
        .searchable(text: $query, prompt: "Search secrets")
        .listStyle(.inset)
        .contextMenu(forSelectionType: String.self) { names in
            if let secret = secret(names.first) {
                if secret.aws == nil {
                    Button("Show Values\u{2026}") { editor = .show(secret) }
                }
                Button("Edit\u{2026}") { open(secret) }
                Button("Delete\u{2026}", role: .destructive) { confirmDelete = secret.name }
            }
        } primaryAction: { names in
            if let secret = secret(names.first) { open(secret) }
        }
        .overlay {
            if model.secrets.isEmpty {
                ContentUnavailableView {
                    Label("No Secrets", systemImage: "key")
                } description: {
                    Text("Add an API key, a token, a website login or an AWS sign-in. An agent then uses it by name, with mayi run, mayi fill or aws --profile, and never sees the value.")
                } actions: {
                    Button("Add Secret") { editor = .new }
                }
            } else if shown.isEmpty, !query.isEmpty {
                ContentUnavailableView.search(text: query)
            } else if shown.isEmpty, let folder {
                ContentUnavailableView(
                    "\(folder) is empty", systemImage: "folder",
                    description: Text("Move a secret here by choosing this folder when you edit it."))
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) { StatusBar(message: error, isError: true) }
        .navigationTitle(folder ?? "Secrets")
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    if let secret = secret(selection) { editor = .show(secret) }
                } label: {
                    Label("Show Values", systemImage: "eye")
                }
                .disabled(secret(selection) == nil || secret(selection)?.aws != nil)
                .help("Show the selected secret's values, after you confirm")
                Button {
                    if let secret = secret(selection) { open(secret) }
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
                    Label("Add", systemImage: "plus")
                }
                .help("Add a secret, a website login or an AWS sign-in")
            }
        }
        .sheet(item: $editor) { target in
            if target.existing == nil {
                AddSheet(model: model, folder: folder, draft: newDraft) { editor = nil }
            } else {
                editor(for: target)
            }
        }
        .sheet(item: $aws) { target in
            switch target {
            case .edit(let secret): AwsSignInEditor(model: model, secret: secret) { aws = nil }
            }
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

    /// A new secret starts in the folder being looked at.
    private var newDraft: SecretDraft {
        var draft = SecretDraft()
        draft.folderText = folder ?? ""
        return draft
    }

    private func editor(for target: EditorTarget) -> some View {
        SecretEditor(
            existing: target.existing,
            onReveal: target.existing.map { secret in { await model.revealSecret(secret) } },
            revealOnOpen: target.revealsAtOnce,
            loadsAtOnce: target.existing.map { model.unlocked && $0.level < 4 } ?? false,
            folders: model.folders,
            onDismissRotation: target.existing.map { secret in { model.dismissRotation(name: secret.name) } },
            onSave: { change in
                let problem = await model.save(change)
                if problem == nil { editor = nil }
                return problem
            },
            onCancel: { editor = nil })
    }
}

/// The Add dialog: its Type picker chooses a secret, a website login or an
/// AWS sign-in, each with its own form below.
struct AddSheet: View {
    @ObservedObject var model: AppModel
    let folder: String?
    let draft: SecretDraft
    let onDone: () -> Void
    @State private var kind: AddKind = .secret

    var body: some View {
        switch kind {
        case .aws:
            AwsSignInSheet(model: model, folder: folder, onPickKind: { kind = $0 }, onDone: onDone)
        case .secret, .login:
            SecretEditor(
                existing: nil,
                draft: {
                    var start = draft
                    start.login = kind == .login
                    return start
                }(),
                folders: model.folders,
                onSave: { change in
                    let problem = await model.save(change)
                    if problem == nil { onDone() }
                    return problem
                },
                onCancel: onDone,
                onPickAws: { kind = .aws })
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

    /// Newest first, split where the calendar day changes. Another device's
    /// withdrawn prompts are left out: the request shows where it was answered.
    private var days: [Day] {
        var days: [Day] = []
        for entry in model.log.reversed() where !(entry.device != nil && entry.outcome == "withdrawn") {
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
    /// Answered on another device, or the agent stopped waiting: not refused.
    private var withdrawn: Bool { entry.outcome == "withdrawn" }

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

    /// The agent, the machine it asked from, and which device answered when
    /// it was another one.
    private var whoAndWhere: String {
        switch (entry.remote, entry.device) {
        case (true, nil): return "\(entry.agent), from \(entry.requester)"
        case (true, let device?): return "\(entry.agent), from \(entry.requester), answered on \(device)"
        case (false, nil): return "\(entry.agent), on this Mac"
        case (false, let device?): return "\(entry.agent), on \(device)"
        }
    }

    private var signIn: Bool { !entry.site.isEmpty }

    private var title: String {
        switch entry.event {
        case "request" where released && signIn:
            let ways = Set(entry.secrets.map { Self.how($0.via) })
            return "Typed \(names) into \(host(entry.site))" + (ways.count == 1 ? " \(ways.first!)" : "")
        case "request" where released:
            let ways = Set(entry.secrets.map { Self.how($0.via) })
            return "Released \(names)" + (ways.count == 1 ? " \(ways.first!)" : "")
        case "request" where withdrawn:
            return "Withdrawn: \(names)"
        case "request":
            return names.isEmpty ? "Request refused" : "Refused \(names)"
        case "stop":
            return signIn ? "Sign-in stopped by you" : "Command stopped by you"
        case "view":
            return "You viewed \(names) on \(entry.device ?? "this Mac")"
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
        guard entry.event == "request", !released, !withdrawn else { return nil }
        let why = entry.outcome.hasPrefix("denied: ") ? String(entry.outcome.dropFirst(8)) : entry.outcome
        return why.prefix(1).uppercased() + why.dropFirst() + "."
    }

    private var symbol: String {
        switch entry.event {
        case "request": return released ? "key" : withdrawn ? "arrow.uturn.backward.circle" : "xmark.circle"
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
                        ? AnyShapeStyle(.primary)
                        : entry.event == "exit" || withdrawn ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.red))
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .foregroundStyle(entry.event == "exit" ? .secondary : .primary)
                if let refusal {
                    Text(refusal).font(.callout).foregroundStyle(.red)
                }
                if withdrawn {
                    Text("Answered on another device, or the agent stopped waiting.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
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
                    Text(whoAndWhere)
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
    @State private var place: Place?

    /// A sidebar row: a section, or a folder of secrets under Secrets.
    private enum Place: Hashable {
        case section(Section)
        case folder(String)
    }

    private var section: Section? {
        switch place {
        case .section(let section): return section
        case .folder: return .secrets
        case nil: return nil
        }
    }
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
        _place = State(initialValue: .section(section))
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
            List(selection: $place) {
                ForEach(Section.allCases) { item in
                    Label(item.rawValue, systemImage: item.symbol)
                        .badge(count(item))
                        .tag(Place.section(item))
                    if item == .secrets {
                        ForEach(model.folders, id: \.self) { folder in
                            Label(folder, systemImage: "folder")
                                .badge(model.secrets.filter { $0.folder == folder }.count)
                                .padding(.leading, 14)
                                .tag(Place.folder(folder))
                        }
                    }
                }
            }
            .listStyle(.sidebar)
            .navigationSplitViewColumnWidth(min: 170, ideal: 190, max: 240)
        } detail: {
            switch place ?? .section(.secrets) {
            case .folder(let folder): SecretsView(model: model, folder: folder).id(folder)
            case .section(.secrets): SecretsView(model: model)
            case .section(.machines): MachinesView(model: model)
            case .section(.devices): DevicesView(model: model)
            case .section(.activity): ActivityView(model: model)
            }
        }
        .frame(minWidth: 720, minHeight: 440)
        .onAppear {
            model.refresh()
            onSection(section ?? .secrets)
        }
        .onChange(of: place) { _, _ in onSection(section ?? .secrets) }
    }
}
