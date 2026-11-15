import Foundation
import Testing

@testable import MayiKit

/// A second device joining the Mac's vault and the two staying in sync, with
/// both ends driven through the same model the windows use.
@MainActor
@Suite(.serialized) struct DevicesTests {
    func model(_ dir: URL, _ name: String, keys: TestKeys, presence: Bool = true) throws -> AppModel {
        let model = AppModel(presence: FixedPresence(present: presence))
        try model.start(
            keys: keys,
            paths: MayiPaths(
                home: dir.appendingPathComponent(name), socket: dir.appendingPathComponent("\(name).sock").path,
                port: 0, advertise: ["127.0.0.1"]),
            deviceName: name)
        return model
    }

    @Test func addingADeviceNeedsTheOwner() async throws {
        let absent = try model(try scratch(), "mac", keys: TestKeys(), presence: false)
        #expect(await absent.startEnrolment() == "Adding a device needs your fingerprint.")
        #expect(absent.enrolmentToken == nil)
    }

    @Test func aSecondDeviceJoinsAndStaysInSync() async throws {
        let dir = try scratch()
        let macKeys = TestKeys()
        let mac = try model(dir, "mac", keys: macKeys)
        #expect(mac.saveSecret(name: "L1", level: 1, values: ["value": "one"], allow: [], maxGrantSecs: 60) == nil)
        #expect(mac.saveSecret(name: "L4", level: 4, values: ["value": "four"], allow: [], maxGrantSecs: 60) == nil)
        #expect(mac.devices.map(\.name) == ["mac"])

        #expect(await mac.startEnrolment() == nil)
        let token = try #require(mac.enrolmentToken)
        #expect(token.hasPrefix("mayid1."))

        // The new device redeems the token off the main thread, as an app would.
        let phoneKeys = TestKeys()
        let phoneHome = dir.appendingPathComponent("phone")
        try FileManager.default.createDirectory(at: phoneHome, withIntermediateDirectories: true)
        let vaultPath = phoneHome.appendingPathComponent("vault.db").path
        try await Task.detached {
            try joinVault(vaultPath: vaultPath, deviceName: "phone", keys: phoneKeys, token: token)
        }.value
        #expect(macKeys.prompts == ["Add phone as a device of this vault"], "sharing the level 4 key asks the Mac's owner once")
        try await eventually { mac.lastDeviceAdded == "phone" }
        #expect(mac.enrolmentToken == nil)

        let phone = try model(dir, "phone", keys: phoneKeys)
        #expect(phone.secrets.map(\.name) == ["L1", "L4"])
        #expect(phone.devices.map(\.name) == ["mac", "phone"])

        // A change on the phone reaches the Mac without anyone asking twice.
        #expect(phone.saveSecret(name: "FROM_PHONE", level: 2, values: ["value": "p"], allow: [], maxGrantSecs: 60) == nil)
        try await eventually { mac.secrets.contains { $0.name == "FROM_PHONE" } }
        // And the Mac now knows where the phone is, so it can start a sync too.
        #expect(mac.saveSecret(name: "FROM_MAC", level: 1, values: ["value": "m"], allow: [], maxGrantSecs: 60) == nil)
        try await eventually { phone.secrets.contains { $0.name == "FROM_MAC" } }

        // The phone can serve its own requests for a level 4 secret written on the Mac.
        let result = try await mayi(
            ["run", "-s", "L4", "-r", "on the phone", "--", "sh", "-c", "echo ${#L4}"],
            socket: dir.appendingPathComponent("phone.sock").path)
        #expect(result.out == "4\n")

        #expect(mac.removeDevice(id: phone.devices.first { $0.thisDevice }!.id) == nil)
        #expect(mac.devices.first { $0.name == "phone" }?.removed == true)
        #expect(mac.rotationAdvice == "Rotate these secrets, which phone could read: FROM_MAC, FROM_PHONE, L1, L4.")
    }

    @Test func aRecoveryKeyRestoresAMacWhoseKeysChanged() async throws {
        let dir = try scratch()
        let mac = try model(dir, "mac", keys: TestKeys())
        #expect(mac.saveSecret(name: "L4", level: 4, values: ["value": "four"], allow: [], maxGrantSecs: 60) == nil)
        #expect(await mac.createRecoveryKey() == nil)
        let key = try #require(mac.recoveryKey)
        #expect(key.hasPrefix("mayi-recovery1."))
        #expect(mac.devices.contains { $0.recovery })
        mac.forgetRecoveryKey()
        #expect(mac.recoveryKey == nil)

        // New fingerprints: the old biometric key is gone for good.
        let vaultPath = dir.appendingPathComponent("mac/vault.db").path
        let newKeys = TestKeys()
        #expect(throws: MayiError.self) {
            _ = try VaultDevice.open(vaultPath: vaultPath, deviceName: "mac", keys: newKeys, ui: SilentUi())
        }
        try recoverVault(vaultPath: vaultPath, deviceName: "mac", keys: newKeys, recoveryKey: key)
        let restored = try VaultDevice.open(vaultPath: vaultPath, deviceName: "mac", keys: newKeys, ui: SilentUi())
        try restored.serve(socketPath: dir.appendingPathComponent("r.sock").path)
        let result = try await mayi(
            ["run", "-s", "L4", "-r", "after recovery", "--", "sh", "-c", "echo ${#L4}"],
            socket: dir.appendingPathComponent("r.sock").path)
        #expect(result.out == "4\n")
    }
}
