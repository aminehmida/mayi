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
        return (try? await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)) ?? false
    }
}
