import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// The device's two keys, generated inside the Secure Enclave.
///
/// The private keys never leave the enclave. What is stored on disk are
/// opaque blobs that only this Mac's enclave can use, sealed with a key in
/// the keychain that only Mayi can read (see `KeyWrap`): the enclave itself
/// would let any program of the user use a blob. The device key works
/// whenever the Mac has been unlocked once. The level 4 key needs the owner
/// for every use: Touch ID, an Apple Watch, or the login password when
/// Touch ID cannot be used (a closed lid, no Touch ID keyboard).
///
/// Macs set up with an earlier version have a fingerprint-only level 4 key
/// (`biometric.sekey`), which their vault's level 4 secrets are encrypted
/// to. It is kept until the Mac sets its vault aside and joins or starts a
/// new one.
public final class SecureEnclaveKeys: KeyStore, @unchecked Sendable {
    private let device: SecureEnclave.P256.KeyAgreement.PrivateKey
    private let biometricBlob: Data
    private let biometricPublicKey: Data
    /// Whether the level 4 key also accepts the password or a watch.
    public let acceptsPassword: Bool

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// Loads the keys stored in `directory`, generating them on first run.
    /// `freshVault` says no vault depends on the keys yet, so an older
    /// fingerprint-only level 4 key can give way to one that also accepts
    /// the password.
    public static func loadOrCreate(
        directory: URL, freshVault: Bool = false, wrap: KeyWrap = KeyWrap()
    ) throws -> SecureEnclaveKeys {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let deviceBlob = try wrap.load(directory.appendingPathComponent("device.sekey")) {
            try SecureEnclave.P256.KeyAgreement.PrivateKey(
                accessControl: accessControl(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [.privateKeyUsage])
            ).dataRepresentation
        }
        let older = directory.appendingPathComponent("biometric.sekey")
        let current = directory.appendingPathComponent("presence.sekey")
        if !wrap.exists(current), wrap.exists(older), !freshVault {
            return try SecureEnclaveKeys(
                deviceBlob: deviceBlob, biometricBlob: try wrap.load(older) { throw KeyWrapError.damaged },
                acceptsPassword: false)
        }
        let presenceBlob = try wrap.load(current) {
            try SecureEnclave.P256.KeyAgreement.PrivateKey(
                accessControl: accessControl(kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence])
            ).dataRepresentation
        }
        return try SecureEnclaveKeys(deviceBlob: deviceBlob, biometricBlob: presenceBlob, acceptsPassword: true)
    }

    init(deviceBlob: Data, biometricBlob: Data, acceptsPassword: Bool) throws {
        self.acceptsPassword = acceptsPassword
        device = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: deviceBlob)
        // Loading the key and reading its public half asks for nothing; only
        // using the private half does.
        biometricPublicKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: biometricBlob)
            .publicKey.x963Representation
        self.biometricBlob = biometricBlob
    }

    private static func accessControl(_ protection: CFString, _ flags: SecAccessControlCreateFlags) throws
        -> SecAccessControl
    {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, protection, flags, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return control
    }

    public func devicePublic() -> Data {
        device.publicKey.x963Representation
    }

    public func biometricPublic() -> Data {
        biometricPublicKey
    }

    public func deviceEcdh(peerPublic: Data) throws -> Data {
        do {
            return try Self.agree(device, peerPublic)
        } catch {
            throw KeyError.Failed(detail: "Secure Enclave: \(error.localizedDescription)")
        }
    }

    /// The Touch ID dialog showing now, so it can be taken down.
    private let promptLock = NSLock()
    private var showing: LAContext?

    public func biometricEcdh(peerPublics: [Data], prompt: String) throws -> [Data] {
        // One context for the whole batch, so the user is asked once.
        let context = LAContext()
        context.localizedReason = prompt
        promptLock.withLock { showing = context }
        defer {
            promptLock.withLock { if showing === context { showing = nil } }
            context.invalidate()
        }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: biometricBlob, authenticationContext: context)
            return try peerPublics.map { try Self.agree(key, $0) }
        } catch let error as NSError where error.domain == LAError.errorDomain {
            throw KeyError.Denied
        } catch {
            throw KeyError.Failed(detail: "Secure Enclave: \(error.localizedDescription)")
        }
    }

    /// Another device answered, or the requester gave up: closes the dialog,
    /// and the check in progress fails as cancelled.
    public func cancelBiometric() {
        promptLock.withLock { showing?.invalidate() }
    }

    private static func agree(_ key: SecureEnclave.P256.KeyAgreement.PrivateKey, _ peer: Data) throws -> Data {
        let peerKey = try P256.KeyAgreement.PublicKey(x963Representation: peer)
        return try key.sharedSecretFromKeyAgreement(with: peerKey).withUnsafeBytes { Data($0) }
    }
}
