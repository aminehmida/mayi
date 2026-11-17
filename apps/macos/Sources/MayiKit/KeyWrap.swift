import CryptoKit
import Foundation
import Security

/// Holds the key that seals the Secure Enclave blobs on disk.
public protocol WrapKeyStore: Sendable {
    /// The 32-byte sealing key; created when there is none and `create`.
    func sealingKey(create: Bool) throws -> SymmetricKey?
}

/// The sealing key, kept in the login keychain.
///
/// A Secure Enclave blob works for any program of the user that has it: the
/// enclave does not know which program asks. The keychain does. It lets only
/// the program that created an item read it back without asking the owner:
/// for a release, any Mayi signed with the same certificate. So another
/// program, an agent included, can read the sealed blobs but not open them.
public struct KeychainWrapKey: WrapKeyStore {
    let service: String

    public init(service: String = "dev.mayi.app.keys") {
        self.service = service
    }

    private var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "sealing key",
        ]
    }

    public func sealingKey(create: Bool) throws -> SymmetricKey? {
        var found = query
        found[kSecReturnData as String] = true
        var data: CFTypeRef?
        switch SecItemCopyMatching(found as CFDictionary, &data) {
        case errSecSuccess:
            guard let bytes = data as? Data, bytes.count == 32 else { throw KeyWrapError.damaged }
            return SymmetricKey(data: bytes)
        case errSecItemNotFound:
            guard create else { return nil }
            let key = SymmetricKey(size: .bits256)
            var add = query
            add[kSecAttrLabel as String] = "Mayi"
            add[kSecAttrDescription as String] = "Protects the Mayi app's keys"
            add[kSecValueData as String] = key.withUnsafeBytes { Data($0) }
            let status = SecItemAdd(add as CFDictionary, nil)
            guard status == errSecSuccess else { throw KeyWrapError.keychain(status) }
            return key
        case let status:
            throw KeyWrapError.keychain(status)
        }
    }
}

/// A sealing key in memory, for tests.
public final class MemoryWrapKey: WrapKeyStore, @unchecked Sendable {
    private var key: SymmetricKey?
    public init() {}
    public func sealingKey(create: Bool) throws -> SymmetricKey? {
        if key == nil, create { key = SymmetricKey(size: .bits256) }
        return key
    }
    /// Forgets the key, as if the keychain item were deleted.
    public func forget() { key = nil }
}

public enum KeyWrapError: Error, LocalizedError {
    case keychain(OSStatus)
    case damaged
    /// Sealed blobs without the key that opens them.
    case missingKey

    public var errorDescription: String? {
        switch self {
        case .keychain(let status):
            let message = (SecCopyErrorMessageString(status, nil) as String?) ?? "error \(status)"
            return "The keychain refused Mayi's keys: \(message)"
        case .damaged:
            return "The keychain item that protects Mayi's keys is damaged."
        case .missingKey:
            return "The keychain item that protects Mayi's keys is missing, so this Mac's keys cannot be opened. "
                + "Restore the keychain, or recover the vault with your recovery key."
        }
    }
}

/// Stores blobs sealed with the sealing key, each bound to its file name so
/// one cannot stand in for another.
public struct KeyWrap: Sendable {
    let store: WrapKeyStore

    public init(store: WrapKeyStore = KeychainWrapKey()) {
        self.store = store
    }

    static func sealedURL(_ plain: URL) -> URL {
        plain.appendingPathExtension("sealed")
    }

    private static func context(_ plain: URL) -> Data {
        Data("mayi/sekey/\(plain.lastPathComponent)".utf8)
    }

    /// Whether a blob is stored for `plain`, sealed or not.
    public func exists(_ plain: URL) -> Bool {
        let fm = FileManager.default
        return fm.fileExists(atPath: Self.sealedURL(plain).path) || fm.fileExists(atPath: plain.path)
    }

    /// The blob for `plain`: opened from its sealed file, sealed now if only
    /// the plain file from an earlier version exists (which is then
    /// deleted), or made with `create` and sealed.
    public func load(_ plain: URL, create: () throws -> Data) throws -> Data {
        let sealed = Self.sealedURL(plain)
        let fm = FileManager.default
        if let box = try? Data(contentsOf: sealed) {
            guard let key = try store.sealingKey(create: false) else { throw KeyWrapError.missingKey }
            do {
                return try AES.GCM.open(AES.GCM.SealedBox(combined: box), using: key, authenticating: Self.context(plain))
            } catch {
                throw KeyWrapError.damaged
            }
        }
        let blob = try (try? Data(contentsOf: plain)) ?? create()
        try save(blob, as: plain)
        if fm.fileExists(atPath: plain.path) {
            try fm.removeItem(at: plain)
        }
        return blob
    }

    private func save(_ blob: Data, as plain: URL) throws {
        guard let key = try store.sealingKey(create: true) else { throw KeyWrapError.missingKey }
        let box = try AES.GCM.seal(blob, using: key, authenticating: Self.context(plain))
        guard let combined = box.combined else { throw KeyWrapError.damaged }
        let sealed = Self.sealedURL(plain)
        try combined.write(to: sealed, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: sealed.path)
    }
}
