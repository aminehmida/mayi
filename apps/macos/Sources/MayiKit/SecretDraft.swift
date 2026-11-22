import Foundation

/// The editor's contents, with the rules for turning them into a change.
public struct SecretDraft: Equatable {
    public struct Field: Identifiable, Equatable {
        public let id = UUID()
        public var name: String
        public var value: String

        public init(name: String, value: String = "") {
            self.name = name
            self.value = value
        }

        public static func == (a: Field, b: Field) -> Bool {
            a.name == b.name && a.value == b.value
        }
    }

    public enum Change: Equatable, Sendable {
        /// Store new values (creating the secret or replacing it).
        case put(
            name: String, level: UInt8, values: [String: String], allow: [String], maxGrantSecs: UInt64,
            login: Bool, sites: [String], tags: [String])
        /// Keep the stored values; change only the rules and the tags.
        case rules(name: String, allow: [String], maxGrantSecs: UInt64, sites: [String], tags: [String])
    }

    public var name = ""
    public var level: UInt8 = 3
    /// A website login rather than a secret for commands.
    public var login = false
    public var fields = [Field(name: "value")]
    /// One command pattern per line.
    public var allowText = ""
    public var maxGrantMinutes = 15

    // A login's fields.
    public var username = ""
    public var password = ""
    /// A new setup key or `otpauth://` link, as a site shows when two-factor
    /// is turned on. Empty keeps the stored one, which is never shown.
    public var twoFactorKey = ""
    /// Drop the stored two-factor key on saving.
    public var removeTwoFactor = false
    /// One website per line.
    public var sitesText = ""
    /// Its tags, separated by commas.
    public var tagsText = ""
    /// The stored values, once shown to the owner: saving them unchanged
    /// changes only the rules. Nil until shown.
    public var shown: [String: String]?

    public init() {}

    public init(editing secret: SecretRecord) {
        name = secret.name
        level = secret.level
        login = secret.login
        fields = secret.fields.map { Field(name: $0) }
        allowText = secret.allow.joined(separator: "\n")
        sitesText = secret.sites.joined(separator: "\n")
        tagsText = secret.tags.joined(separator: ", ")
        maxGrantMinutes = Int(secret.maxGrantSecs / 60)
    }

    /// Fills the fields with the stored values, so they can be read and
    /// edited. A login's two-factor key stays out of its field: the editor
    /// shows the code it gives instead.
    public mutating func show(_ revealed: RevealedSecret) {
        var values: [String: String] = [:]
        for field in revealed.fields { values[field.name] = field.value }
        shown = values
        if login {
            username = values["username"] ?? ""
            password = values["password"] ?? ""
            twoFactorKey = ""
        } else if Set(fields.map(\.name)) == Set(values.keys) {
            // Filled in place: the rows keep their identity, so an eye that
            // asked for the values stays open once they arrive.
            for index in fields.indices { fields[index].value = values[fields[index].name] ?? "" }
        } else {
            fields = revealed.fields.map { Field(name: $0.name, value: $0.value) }
        }
    }

    private static func lines(_ text: String) -> [String] {
        text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    /// The two-factor key saving would keep: a new one typed, else the stored one.
    public var effectiveTwoFactorKey: String? {
        let typed = twoFactorKey.trimmingCharacters(in: .whitespaces)
        if !typed.isEmpty { return typed }
        return removeTwoFactor ? nil : shown?["totp"]
    }

    var allow: [String] { Self.lines(allowText) }
    /// The tags typed, trimmed, without empty ones.
    var tags: [String] {
        tagsText.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
    var sites: [String] { Self.lines(sitesText) }

    /// What saving should do, or why it cannot be saved. When editing, leaving
    /// every value empty keeps the stored values, which is the only way to
    /// edit a level 4 secret without replacing it.
    public func change(existing: SecretRecord?) -> Result<Change, DraftError> {
        let name = name.trimmingCharacters(in: .whitespaces)
        if name.isEmpty { return .failure(login ? "Give the login a name." : "Give the secret a name.") }
        let maxGrantSecs = UInt64(max(0, maxGrantMinutes)) * 60
        if login { return loginChange(name: name, existing: existing, maxGrantSecs: maxGrantSecs) }

        let names = fields.map { $0.name.trimmingCharacters(in: .whitespaces) }
        if names.contains("") { return .failure("Every field needs a name.") }
        if Set(names).count != names.count { return .failure("Field names must be different.") }

        if let existing, fields.allSatisfy({ $0.value.isEmpty }) {
            if level != existing.level {
                return .failure("Changing the level re-encrypts the secret, so enter its values again.")
            }
            if Set(names) != Set(existing.fields) {
                return .failure("Changing the fields replaces the secret, so enter its values.")
            }
            return .success(.rules(name: name, allow: allow, maxGrantSecs: maxGrantSecs, sites: [], tags: tags))
        }
        if fields.contains(where: { $0.value.isEmpty }) {
            return .failure("Enter a value for every field.")
        }
        let values = Dictionary(uniqueKeysWithValues: zip(names, fields.map(\.value)))
        if let existing, values == shown, level == existing.level {
            return .success(.rules(name: name, allow: allow, maxGrantSecs: maxGrantSecs, sites: [], tags: tags))
        }
        return .success(
            .put(name: name, level: level, values: values, allow: allow, maxGrantSecs: maxGrantSecs, login: false, sites: [], tags: tags))
    }

    private func loginChange(name: String, existing: SecretRecord?, maxGrantSecs: UInt64) -> Result<Change, DraftError> {
        if sites.isEmpty { return .failure("Add the website this login is for.") }
        // A stored login's values change only once shown, so that whatever is
        // not retyped is kept rather than dropped.
        if let existing, shown == nil {
            if [username, password, twoFactorKey].contains(where: { !$0.isEmpty }) {
                return .failure("Show the login's values to change them.")
            }
            if level != existing.level {
                return .failure("Changing the level re-encrypts the login, so show its values first.")
            }
            return .success(.rules(name: name, allow: [], maxGrantSecs: maxGrantSecs, sites: sites, tags: tags))
        }
        if password.isEmpty { return .failure("Enter the password.") }
        var values = ["password": password]
        let user = username.trimmingCharacters(in: .whitespaces)
        if !user.isEmpty { values["username"] = user }
        if let key = effectiveTwoFactorKey { values["totp"] = key }
        if let existing, values == shown, level == existing.level {
            return .success(.rules(name: name, allow: [], maxGrantSecs: maxGrantSecs, sites: sites, tags: tags))
        }
        return .success(
            .put(name: name, level: level, values: values, allow: [], maxGrantSecs: maxGrantSecs, login: true, sites: sites, tags: tags))
    }
}

public struct DraftError: Error, Equatable, ExpressibleByStringLiteral {
    public let message: String

    public init(stringLiteral value: String) {
        message = value
    }
}
