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

    public enum Change: Equatable {
        /// Store new values (creating the secret or replacing it).
        case put(
            name: String, level: UInt8, values: [String: String], allow: [String], maxGrantSecs: UInt64,
            login: Bool, sites: [String])
        /// Keep the stored values; change only the rules.
        case rules(name: String, allow: [String], maxGrantSecs: UInt64, sites: [String])
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
    /// The setup key or `otpauth://` link a site shows when two-factor is turned on.
    public var twoFactorKey = ""
    /// One website per line.
    public var sitesText = ""

    public init() {}

    public init(editing secret: SecretRecord) {
        name = secret.name
        level = secret.level
        login = secret.login
        fields = secret.fields.map { Field(name: $0) }
        allowText = secret.allow.joined(separator: "\n")
        sitesText = secret.sites.joined(separator: "\n")
        maxGrantMinutes = Int(secret.maxGrantSecs / 60)
    }

    private static func lines(_ text: String) -> [String] {
        text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    var allow: [String] { Self.lines(allowText) }
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
            return .success(.rules(name: name, allow: allow, maxGrantSecs: maxGrantSecs, sites: []))
        }
        if fields.contains(where: { $0.value.isEmpty }) {
            return .failure("Enter a value for every field.")
        }
        let values = Dictionary(uniqueKeysWithValues: zip(names, fields.map(\.value)))
        return .success(
            .put(name: name, level: level, values: values, allow: allow, maxGrantSecs: maxGrantSecs, login: false, sites: []))
    }

    private func loginChange(name: String, existing: SecretRecord?, maxGrantSecs: UInt64) -> Result<Change, DraftError> {
        if sites.isEmpty { return .failure("Add the website this login is for.") }
        let entered = [username, password, twoFactorKey].contains { !$0.isEmpty }
        if let existing, !entered {
            if level != existing.level {
                return .failure("Changing the level re-encrypts the login, so enter its password again.")
            }
            return .success(.rules(name: name, allow: [], maxGrantSecs: maxGrantSecs, sites: sites))
        }
        if password.isEmpty { return .failure("Enter the password.") }
        var values = ["password": password]
        let user = username.trimmingCharacters(in: .whitespaces)
        if !user.isEmpty { values["username"] = user }
        let key = twoFactorKey.trimmingCharacters(in: .whitespaces)
        if !key.isEmpty { values["totp"] = key }
        return .success(
            .put(name: name, level: level, values: values, allow: [], maxGrantSecs: maxGrantSecs, login: true, sites: sites))
    }
}

public struct DraftError: Error, Equatable, ExpressibleByStringLiteral {
    public let message: String

    public init(stringLiteral value: String) {
        message = value
    }
}
