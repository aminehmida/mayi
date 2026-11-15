import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// The device's two keys, generated inside the Secure Enclave.
///
/// The private keys never leave the enclave. What is stored on disk are
/// opaque blobs that only this Mac's enclave can use. The device key works
/// whenever the Mac has been unlocked once; the biometric key requires a
/// fingerprint for every use and is invalidated if the enrolled fingerprints
/// change.
public final class SecureEnclaveKeys: KeyStore, @unchecked Sendable {
    private let device: SecureEnclave.P256.KeyAgreement.PrivateKey
    private let biometricBlob: Data
    private let biometricPublicKey: Data

    public static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// Loads the keys stored in `directory`, generating them on first run.
    public static func loadOrCreate(directory: URL) throws -> SecureEnclaveKeys {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let deviceBlob = try blob(at: directory.appendingPathComponent("device.sekey")) {
            try SecureEnclave.P256.KeyAgreement.PrivateKey(
                accessControl: accessControl(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [.privateKeyUsage])
            ).dataRepresentation
        }
        let biometricBlob = try blob(at: directory.appendingPathComponent("biometric.sekey")) {
            try SecureEnclave.P256.KeyAgreement.PrivateKey(
                accessControl: accessControl(
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet])
            ).dataRepresentation
        }
        return try SecureEnclaveKeys(deviceBlob: deviceBlob, biometricBlob: biometricBlob)
    }

    init(deviceBlob: Data, biometricBlob: Data) throws {
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

    private static func blob(at url: URL, create: () throws -> Data) throws -> Data {
        if let existing = try? Data(contentsOf: url) {
            return existing
        }
        let data = try create()
        try data.write(to: url, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return data
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

    public func biometricEcdh(peerPublics: [Data], prompt: String) throws -> [Data] {
        // One context for the whole batch, so the user is asked once.
        let context = LAContext()
        context.localizedReason = prompt
        defer { context.invalidate() }
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

    private static func agree(_ key: SecureEnclave.P256.KeyAgreement.PrivateKey, _ peer: Data) throws -> Data {
        let peerKey = try P256.KeyAgreement.PublicKey(x963Representation: peer)
        return try key.sharedSecretFromKeyAgreement(with: peerKey).withUnsafeBytes { Data($0) }
    }
}
