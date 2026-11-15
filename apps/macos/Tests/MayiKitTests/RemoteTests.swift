import Foundation
import Testing

@testable import MayiKit

/// Another machine pairing with the app and using it over the network: the
/// real CLI, with no local socket and its own config, against the app model.
@MainActor
@Suite(.serialized) struct RemoteTests {
    let model: AppModel
    let dir: URL
    /// The CLI acting as another machine.
    var machine: [String: String] {
        ["MAYI_CONFIG": dir.appendingPathComponent("requester.json").path, "HOME": dir.appendingPathComponent("nohome").path]
    }

    init() throws {
        dir = try scratch()
        model = AppModel(presence: FixedPresence())
        try model.start(
            keys: TestKeys(),
            paths: MayiPaths(
                home: dir.appendingPathComponent("home"), socket: dir.appendingPathComponent("s.sock").path,
                port: 0, advertise: ["127.0.0.1"]),
            deviceName: "test-mac")
        #expect(model.saveSecret(name: "L1", level: 1, values: ["value": "remote-secret"], allow: [], maxGrantSecs: 60) == nil)
    }

    @Test func pairingNeedsTheOwner() async throws {
        let absent = AppModel(presence: FixedPresence(present: false))
        let other = try scratch()
        try absent.start(
            keys: TestKeys(),
            paths: MayiPaths(home: other.appendingPathComponent("home"), socket: other.appendingPathComponent("s.sock").path, port: 0),
            deviceName: "test")
        #expect(await absent.startPairing() == "Pairing needs your fingerprint.")
        #expect(absent.pairingToken == nil)
    }

    @Test func aPairedMachineRequestsOverTheNetwork() async throws {
        #expect(try await mayi(["list", "--remote"], environment: machine).status == 69, "not paired yet")

        #expect(await model.startPairing() == nil)
        let token = try #require(model.pairingToken)
        let paired = try await mayi(["pair", token, "--name", "build-vm"], environment: machine)
        #expect(paired.status == 0)
        #expect(paired.out == "Paired with test-mac as build-vm.\n")
        try await eventually { model.lastPaired == "build-vm" }
        #expect(model.pairingToken == nil, "the invitation is spent")
        #expect(model.machines.map(\.name) == ["build-vm"])

        async let run = mayi(
            ["run", "--remote", "-s", "L1", "-r", "from the vm", "--", "sh", "-c", "sleep 0.3; echo $L1"],
            environment: machine)
        // A level 1 secret asked for by another machine is not silent.
        try await eventually { !model.notices.isEmpty }
        let request = model.notices[0].notice.request
        #expect(request.remote && request.requester.hasPrefix("build-vm ("))
        let result = try await run
        #expect(result.status == 0 && result.out == "[masked]\n")

        #expect(model.revokeMachine(id: model.machines[0].id) == nil)
        let refused = try await mayi(["list", "--remote"], environment: machine)
        #expect(refused.status == 69)
        #expect(refused.err.contains("this machine is not paired"))
    }
}
