import AppKit
import CryptoKit
import Foundation
import Security
import Testing

@testable import MayiKit

@Suite struct VaultDeviceTests {
    /// CryptoKit's ECDH output must be what the Rust core derives keys from.
    @Test func swiftKeysOpenAVaultCreatedByTheCore() throws {
        let dir = try scratch()
        let keys = TestKeys()
        let path = dir.appendingPathComponent("vault.db").path
        do {
            let device = try VaultDevice.open(vaultPath: path, deviceName: "test", keys: keys, ui: SilentUi())
            _ = try device.putSecret(
                name: "TOKEN", level: 3, values: ["value": "abc"], allow: ["make *"], maxGrantSecs: 60, login: false,
                sites: [], tags: [])
            _ = try device.putSecret(
                name: "PROD", level: 4, values: ["value": "xyz"], allow: [], maxGrantSecs: 60, login: false, sites: [], tags: [])
        }
        let reopened = try VaultDevice.open(vaultPath: path, deviceName: "test", keys: keys, ui: SilentUi())
        let secrets = try reopened.listSecrets()
        #expect(secrets.map(\.name) == ["PROD", "TOKEN"])
        #expect(secrets[1].allow == ["make *"])
        #expect(keys.prompts.isEmpty, "writing and listing never ask for biometrics")

        let updated = try reopened.updateRules(name: "PROD", allow: ["deploy"], maxGrantSecs: 120, sites: [], tags: [])
        #expect(updated.version > secrets[0].version && updated.level == 4)

        #expect(throws: MayiError.self) {
            _ = try VaultDevice.open(vaultPath: path, deviceName: "x", keys: TestKeys(), ui: SilentUi())
        }
    }

    @Test func loginsKeepTheirWebsites() throws {
        let dir = try scratch()
        let device = try VaultDevice.open(
            vaultPath: dir.appendingPathComponent("vault.db").path, deviceName: "test", keys: TestKeys(), ui: SilentUi())
        let saved = try device.putSecret(
            name: "github", level: 3,
            values: ["username": "amine", "password": "pw", "totp": "JBSWY3DPEHPK3PXP"], allow: [],
            maxGrantSecs: 600, login: true, sites: ["https://GitHub.com/login"], tags: [])
        #expect(saved.login && saved.sites == ["github.com"])
        #expect(saved.fields == ["password", "totp", "username"])
        let moved = try device.updateRules(name: "github", allow: [], maxGrantSecs: 60, sites: ["gitlab.com"], tags: [])
        #expect(moved.sites == ["gitlab.com"])
        #expect(throws: MayiError.self) {
            _ = try device.putSecret(
                name: "bad", level: 3, values: ["password": "pw", "totp": "not a key!"], allow: [], maxGrantSecs: 0,
                login: true, sites: ["a.com"], tags: [])
        }
    }

    /// The real Secure Enclave, as far as it goes without a fingerprint:
    /// key generation, persistence, and unwrapping the vault key.
    @Test(.enabled(if: SecureEnclaveKeys.isAvailable))
    func secureEnclaveKeysPersistAndOpenTheVault() throws {
        let dir = try scratch()
        let keyDir = dir.appendingPathComponent("keys")
        let path = dir.appendingPathComponent("vault.db").path
        // An in-memory sealing key: tests leave the login keychain alone.
        let wrap = KeyWrap(store: MemoryWrapKey())
        let first: SecureEnclaveKeys
        do {
            first = try SecureEnclaveKeys.loadOrCreate(directory: keyDir, wrap: wrap)
        } catch let error as NSError where error.code == Int(errSecInteractionNotAllowed) {
            // The Secure Enclave makes no keys while the Mac is locked.
            return
        }
        #expect(first.devicePublic().count == 65 && first.biometricPublic().count == 65)
        #expect(first.devicePublic() != first.biometricPublic())
        do {
            let device = try VaultDevice.open(vaultPath: path, deviceName: "mac", keys: first, ui: SilentUi())
            _ = try device.putSecret(
                name: "PROD", level: 4, values: ["value": "xyz"], allow: [], maxGrantSecs: 60, login: false, sites: [], tags: [])
        }

        let second = try SecureEnclaveKeys.loadOrCreate(directory: keyDir, wrap: wrap)
        #expect(second.devicePublic() == first.devicePublic())
        #expect(second.biometricPublic() == first.biometricPublic())
        let reopened = try VaultDevice.open(vaultPath: path, deviceName: "mac", keys: second, ui: SilentUi())
        #expect(try reopened.listSecrets().map(\.name) == ["PROD"])

        let mode = try FileManager.default.attributesOfItem(
            atPath: keyDir.appendingPathComponent("presence.sekey.sealed").path)[.posixPermissions] as? Int
        #expect(mode == 0o600)
        #expect(!FileManager.default.fileExists(atPath: keyDir.appendingPathComponent("device.sekey").path))
        #expect(first.acceptsPassword)

        // Another program has the files but not the keychain item.
        #expect(throws: KeyWrapError.self) {
            try SecureEnclaveKeys.loadOrCreate(directory: keyDir, wrap: KeyWrap(store: MemoryWrapKey()))
        }
    }

    /// A Mac set up by an earlier version keeps its fingerprint-only level 4
    /// key while a vault depends on it, and gets one that also accepts the
    /// password once it starts over.
    @Test(.enabled(if: SecureEnclaveKeys.isAvailable))
    func anOlderFingerprintOnlyKeyIsKeptUntilTheVaultStartsOver() throws {
        let keyDir = try scratch().appendingPathComponent("keys")
        try FileManager.default.createDirectory(at: keyDir, withIntermediateDirectories: true)
        var error: Unmanaged<CFError>?
        let control = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error)!
        let older: SecureEnclave.P256.KeyAgreement.PrivateKey
        do {
            older = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: control)
        } catch let error as NSError where error.code == Int(errSecInteractionNotAllowed) {
            return
        }
        try older.dataRepresentation.write(to: keyDir.appendingPathComponent("biometric.sekey"))

        let wrap = KeyWrap(store: MemoryWrapKey())
        let kept = try SecureEnclaveKeys.loadOrCreate(directory: keyDir, wrap: wrap)
        #expect(!kept.acceptsPassword)
        #expect(kept.biometricPublic() == older.publicKey.x963Representation)

        let fresh = try SecureEnclaveKeys.loadOrCreate(directory: keyDir, freshVault: true, wrap: wrap)
        #expect(fresh.acceptsPassword)
        #expect(fresh.biometricPublic() != older.publicKey.x963Representation)
        #expect(fresh.devicePublic() == kept.devicePublic(), "the device key, and so the device's identity, stays")
        let after = try SecureEnclaveKeys.loadOrCreate(directory: keyDir, wrap: wrap)
        #expect(after.biometricPublic() == fresh.biometricPublic(), "the new key is used from then on")
    }

    /// Tags are typed separated by commas; an ACL being edited counts what
    /// it grants, through tags or by name.
    @Test func tagsAndAclDrafts() {
        var draft = SecretDraft()
        draft.tagsText = " work, , ci "
        #expect(draft.tags == ["work", "ci"])

        let tagged = SecretRecord(
            name: "CI_TOKEN", level: 3, fields: ["value"], allow: [], maxGrantSecs: 0, version: 1, login: false,
            sites: [], copies: 1, tags: ["CI"], rotate: [], aws: nil)
        let plain = SecretRecord(
            name: "PROD_DB", level: 3, fields: ["value"], allow: [], maxGrantSecs: 0, version: 1, login: false,
            sites: [], copies: 1, tags: [], rotate: [], aws: nil)
        var acl = AclDraft()
        #expect(acl.isEmpty && !acl.allows(tagged))
        acl.tags = ["ci"]
        #expect(acl.allows(tagged) && !acl.allows(plain), "tags match whatever their case")
        acl.secrets = ["PROD_DB"]
        #expect(acl.allows(plain))
        #expect(acl.record == AclRecord(all: false, tags: ["ci"], secrets: ["PROD_DB"]))
        #expect(aclSummary(acl.record) == "#ci, PROD_DB")
        #expect(aclSummary(AclRecord(all: true, tags: [], secrets: [])) == "all secrets")
        #expect(aclSummary(AclRecord(all: false, tags: [], secrets: [])) == "nothing")
    }

    /// Blobs from an earlier version are sealed on first load and the plain
    /// files deleted; a sealed blob opens only with its own key and under
    /// its own name.
    @Test func keyBlobsAreSealedWithTheKeychainKey() throws {
        let dir = try scratch()
        let plain = dir.appendingPathComponent("device.sekey")
        try Data("enclave blob".utf8).write(to: plain)
        let store = MemoryWrapKey()
        let wrap = KeyWrap(store: store)
        #expect(try wrap.load(plain) { Data() } == Data("enclave blob".utf8))
        #expect(!FileManager.default.fileExists(atPath: plain.path))
        let sealed = dir.appendingPathComponent("device.sekey.sealed")
        #expect(try Data(contentsOf: sealed) != Data("enclave blob".utf8))
        #expect(try wrap.load(plain) { Data("not used".utf8) } == Data("enclave blob".utf8))

        // Moved under another key's name, it does not open.
        let other = dir.appendingPathComponent("presence.sekey")
        try FileManager.default.copyItem(at: sealed, to: dir.appendingPathComponent("presence.sekey.sealed"))
        #expect(throws: KeyWrapError.self) { try wrap.load(other) { Data() } }

        // Without the keychain item, the keys cannot be opened, and none is made up.
        store.forget()
        #expect(throws: KeyWrapError.self) { try wrap.load(plain) { Data() } }
        #expect(try store.sealingKey(create: false) == nil)
    }
}

/// Not a test of its own: with MAYI_SMOKE_HOME set, fills a vault there using
/// the real Secure Enclave keys, so the built app can be launched against it
/// and exercised from the command line.
@Suite struct SmokeVault {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["MAYI_SMOKE_HOME"] != nil))
    func prepare() throws {
        let home = URL(fileURLWithPath: ProcessInfo.processInfo.environment["MAYI_SMOKE_HOME"]!)
        let paths = MayiPaths(home: home, socket: "")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let keys = try SecureEnclaveKeys.loadOrCreate(directory: paths.keys)
        let device = try VaultDevice.open(
            vaultPath: paths.vault.path, deviceName: "smoke", keys: keys, ui: SilentUi())
        for level in UInt8(1)...4 {
            _ = try device.putSecret(
                name: "L\(level)", level: level, values: ["value": "smoke-secret-\(level)"], allow: [],
                maxGrantSecs: 600, login: false, sites: [], tags: [])
        }
        if let site = ProcessInfo.processInfo.environment["MAYI_SMOKE_SITE"] {
            _ = try device.putSecret(
                name: "smoke-login", level: 1,
                values: ["username": "amine@example.com", "password": "hunter2-correct-horse"], allow: [],
                maxGrantSecs: 600, login: true, sites: [site], tags: [])
        }
    }
}

@Suite struct SecretDraftTests {
    let stored = SecretRecord(
        name: "DB", level: 4, fields: ["user", "password"], allow: ["psql *"], maxGrantSecs: 600, version: 1,
        login: false, sites: [], copies: 1, tags: [], rotate: [], aws: nil)
    let storedLogin = SecretRecord(
        name: "github", level: 3, fields: ["password", "totp", "username"], allow: [], maxGrantSecs: 600, version: 1,
        login: true, sites: ["github.com"], copies: 2, tags: [], rotate: [], aws: nil)

    @Test func newSecretNeedsNameAndValues() {
        var draft = SecretDraft()
        #expect(draft.change(existing: nil) == .failure("Give the secret a name."))
        draft.name = "TOKEN"
        #expect(draft.change(existing: nil) == .failure("Enter a value for every field."))
        draft.fields[0].value = "abc"
        draft.allowText = "gh *\n\n  make deploy  "
        draft.maxGrantMinutes = 5
        #expect(
            draft.change(existing: nil)
                == .success(
                    .put(
                        name: "TOKEN", level: 3, values: ["value": "abc"], allow: ["gh *", "make deploy"],
                        maxGrantSecs: 300, login: false, sites: [], tags: [])))
        draft.fields.append(.init(name: "value", value: "x"))
        #expect(draft.change(existing: nil) == .failure("Field names must be different."))
    }

    @Test func editingWithoutValuesChangesOnlyRules() {
        var draft = SecretDraft(editing: stored)
        #expect(draft.maxGrantMinutes == 10)
        draft.allowText = "psql *\npg_dump *"
        #expect(
            draft.change(existing: stored)
                == .success(.rules(name: "DB", allow: ["psql *", "pg_dump *"], maxGrantSecs: 600, sites: [], tags: [])))
    }

    @Test func changingLevelOrFieldsNeedsValues() {
        var draft = SecretDraft(editing: stored)
        draft.level = 3
        #expect(
            draft.change(existing: stored)
                == .failure("Changing the level re-encrypts the secret, so enter its values again."))
        draft.fields[0].value = "admin"
        #expect(draft.change(existing: stored) == .failure("Enter a value for every field."))
        draft.fields[1].value = "pw"
        #expect(
            draft.change(existing: stored)
                == .success(
                    .put(
                        name: "DB", level: 3, values: ["user": "admin", "password": "pw"], allow: ["psql *"],
                        maxGrantSecs: 600, login: false, sites: [], tags: [])))
    }

    @Test func newLoginNeedsAWebsiteAndAPassword() {
        var draft = SecretDraft()
        draft.login = true
        draft.name = "github"
        #expect(draft.change(existing: nil) == .failure("Add the website this login is for."))
        draft.sitesText = "github.com\n\n *.github.com "
        #expect(draft.change(existing: nil) == .failure("Enter the password."))
        draft.username = " amine "
        draft.password = "pw"
        #expect(
            draft.change(existing: nil)
                == .success(
                    .put(
                        name: "github", level: 3, values: ["username": "amine", "password": "pw"], allow: [],
                        maxGrantSecs: 900, login: true, sites: ["github.com", "*.github.com"], tags: [])))
        draft.twoFactorKey = "JBSW Y3DP"
        guard case .success(.put(_, _, let values, _, _, _, _, _)) = draft.change(existing: nil) else {
            Issue.record("expected a put")
            return
        }
        #expect(values["totp"] == "JBSW Y3DP")
    }

    @Test func editingALoginWithoutValuesChangesOnlyItsWebsites() {
        var draft = SecretDraft(editing: storedLogin)
        #expect(draft.login && draft.sitesText == "github.com")
        draft.sitesText = "github.com\ngist.github.com"
        #expect(
            draft.change(existing: storedLogin)
                == .success(.rules(name: "github", allow: [], maxGrantSecs: 600, sites: ["github.com", "gist.github.com"], tags: [])))
        draft.username = "amine"
        #expect(draft.change(existing: storedLogin) == .failure("Show the login's values to change them."))
        draft.username = ""
        draft.level = 4
        #expect(
            draft.change(existing: storedLogin)
                == .failure("Changing the level re-encrypts the login, so show its values first."))
    }

    @Test func shownValuesSavedUnchangedChangeOnlyRules() {
        var draft = SecretDraft(editing: stored)
        let rows = draft.fields.map(\.id)
        draft.show(RevealedSecret(
            fields: [RevealedField(name: "user", value: "admin"), RevealedField(name: "password", value: "pw")]))
        #expect(draft.fields.map(\.value) == ["admin", "pw"])
        #expect(draft.fields.map(\.id) == rows, "rows keep their identity, so an open eye stays open")
        draft.allowText = "psql *\npg_dump *"
        #expect(
            draft.change(existing: stored)
                == .success(.rules(name: "DB", allow: ["psql *", "pg_dump *"], maxGrantSecs: 600, sites: [], tags: [])))
        // Shown values make a level change possible without typing them again.
        draft.level = 3
        #expect(
            draft.change(existing: stored)
                == .success(
                    .put(
                        name: "DB", level: 3, values: ["user": "admin", "password": "pw"],
                        allow: ["psql *", "pg_dump *"], maxGrantSecs: 600, login: false, sites: [], tags: [])))
    }

    @Test func aShownLoginKeepsItsTwoFactorKeyOutOfSight() {
        var draft = SecretDraft(editing: storedLogin)
        draft.show(RevealedSecret(
            fields: [
                RevealedField(name: "password", value: "pw"), RevealedField(name: "totp", value: "JBSWY3DPEHPK3PXP"),
                RevealedField(name: "username", value: "amine"),
            ]))
        #expect((draft.username, draft.password, draft.twoFactorKey) == ("amine", "pw", ""), "the key is never shown")
        #expect(draft.effectiveTwoFactorKey == "JBSWY3DPEHPK3PXP", "but it is kept")
        #expect(
            draft.change(existing: storedLogin)
                == .success(.rules(name: "github", allow: [], maxGrantSecs: 600, sites: ["github.com"], tags: [])))
        func values(_ draft: SecretDraft) -> [String: String]? {
            guard case .success(.put(_, _, let values, _, _, _, _, _)) = draft.change(existing: storedLogin) else { return nil }
            return values
        }
        draft.password = "new"
        #expect(values(draft) == ["username": "amine", "password": "new", "totp": "JBSWY3DPEHPK3PXP"])
        draft.twoFactorKey = " GEZDGNBVGY3TQOJQ "
        #expect(values(draft)?["totp"] == "GEZDGNBVGY3TQOJQ", "a new key replaces it")
        draft.twoFactorKey = ""
        draft.removeTwoFactor = true
        #expect(values(draft) == ["username": "amine", "password": "new"], "or it is removed")
    }

    @Test func twoFactorCodesComeFromTheKey() throws {
        let code = try twoFactorCode(key: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        #expect(code.code.count == 6 && code.code.allSatisfy(\.isNumber))
        #expect((1...30).contains(code.validSecs))
        #expect(throws: MayiError.self) { _ = try twoFactorCode(key: "not a key!") }
        #expect(TwoFactorCodeRow.grouped("123456") == "123 456")
        #expect(TwoFactorCodeRow.grouped("12345678") == "1234 5678")
    }

    @Test func aCopiedQRCodeIsRead() throws {
        let board = NSPasteboard(name: .init("mayi-test-\(UUID().uuidString)"))
        defer { board.releaseGlobally() }
        #expect(qrCode(on: board) == nil)
        let link = "otpauth://totp/GitHub:amine?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
        board.clearContents()
        let image: NSImage? = qrCode(link)
        board.writeObjects([try #require(image)])
        #expect(qrCode(on: board) == link)
    }
}
