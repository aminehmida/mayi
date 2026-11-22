import SwiftUI

/// An ACL being edited: every secret, or chosen tags and secrets.
struct AclDraft: Equatable {
    var all = false
    var tags: Set<String> = []
    var secrets: Set<String> = []

    init(_ acl: AclRecord? = nil) {
        guard let acl else { return }
        all = acl.all
        tags = Set(acl.tags)
        secrets = Set(acl.secrets)
    }

    var record: AclRecord {
        AclRecord(all: all, tags: tags.sorted(), secrets: secrets.sorted())
    }

    /// Grants nothing, so there is nothing to save yet.
    var isEmpty: Bool { !all && tags.isEmpty && secrets.isEmpty }

    func allows(_ secret: SecretRecord) -> Bool {
        all || secrets.contains(secret.name)
            || secret.tags.contains { tag in tags.contains { $0.caseInsensitiveCompare(tag) == .orderedSame } }
    }
}

/// "all secrets", "#ci, #work, PROD_DB", or "nothing", for a machine's row.
func aclSummary(_ acl: AclRecord) -> String {
    if acl.all { return "all secrets" }
    let parts = acl.tags.map { "#\($0)" } + acl.secrets
    return parts.isEmpty ? "nothing" : parts.joined(separator: ", ")
}

/// Chooses which secrets a machine may use: every secret, whole tags, or
/// single secrets. Nothing is ticked to start with for a new machine, and it
/// cannot be confirmed until something is.
public struct AclEditor: View {
    let title: String
    let message: String
    let confirm: String
    let tags: [String]
    let secrets: [SecretRecord]
    let onConfirm: (AclRecord) -> Void
    let onCancel: () -> Void
    @State private var draft: AclDraft
    @State private var query = ""

    public init(
        title: String, message: String, confirm: String, acl: AclRecord?, tags: [String], secrets: [SecretRecord],
        onConfirm: @escaping (AclRecord) -> Void, onCancel: @escaping () -> Void
    ) {
        self.title = title
        self.message = message
        self.confirm = confirm
        self.tags = tags
        self.secrets = secrets
        self.onConfirm = onConfirm
        self.onCancel = onCancel
        _draft = State(initialValue: AclDraft(acl))
    }

    private func toggle(_ set: WritableKeyPath<AclDraft, Set<String>>, _ value: String) -> Binding<Bool> {
        Binding(
            get: { draft[keyPath: set].contains(value) },
            set: { on in
                if on { draft[keyPath: set].insert(value) } else { draft[keyPath: set].remove(value) }
            })
    }

    private var shownSecrets: [SecretRecord] {
        let words = query.lowercased().split(separator: " ").map(String.init)
        return secrets.filter { secret in
            let text = ([secret.name] + secret.tags).joined(separator: " ").lowercased()
            return words.allSatisfy { text.contains($0) }
        }
    }

    private var granted: Int { secrets.filter(draft.allows).count }

    public var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(title).font(.headline)
                        Text(message)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.vertical, 2)
                }
                Section {
                    Toggle("All secrets, including ones added later", isOn: $draft.all)
                }
                if !draft.all {
                    if !tags.isEmpty {
                        Section {
                            ForEach(tags, id: \.self) { tag in
                                Toggle(isOn: toggle(\.tags, tag)) {
                                    HStack {
                                        Label(tag, systemImage: "tag")
                                        Spacer()
                                        Text("\(secrets.filter { $0.tags.contains(tag) }.count)")
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                        } header: {
                            Text("Tags")
                        } footer: {
                            Text("A tag covers the secrets that carry it now and any tagged later.")
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    Section("Secrets") {
                        TextField("Search", text: $query, prompt: Text("Search secrets"))
                            .labelsHidden()
                        ForEach(shownSecrets, id: \.name) { secret in
                            Toggle(isOn: toggle(\.secrets, secret.name)) {
                                HStack {
                                    Text(secret.name).font(.system(.body, design: .monospaced))
                                    Spacer()
                                    // Granted through a tag already: no need to tick it.
                                    if !draft.secrets.contains(secret.name) && draft.allows(secret) {
                                        Text("through a tag").font(.callout).foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Text(draft.all ? "Can use every secret" : "Can use \(granted) of \(secrets.count) secrets")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Cancel", role: .cancel, action: onCancel).keyboardShortcut(.cancelAction)
                Button(confirm) { onConfirm(draft.record) }
                    .keyboardShortcut(.defaultAction)
                    .disabled(draft.isEmpty)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
        }
        .frame(width: 480, height: 580)
    }
}
