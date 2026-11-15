import LocalAuthentication

/// Proof that the owner is at the device, for actions that widen who can ask
/// for secrets. Nothing is decrypted by it, so it is a policy check, unlike
/// the level 4 key which is enforced by the Secure Enclave.
public protocol PresenceCheck: Sendable {
    func confirm(reason: String) async -> Bool
}

public struct BiometricPresence: PresenceCheck {
    public init() {}

    public func confirm(reason: String) async -> Bool {
        let context = LAContext()
        // Touch ID, an Apple Watch, or the login password when neither can be used.
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }
}
