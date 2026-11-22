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
        #expect(await absent.startPairing(acl: AclRecord(all: true, tags: [], secrets: [])) == "Pairing needs you to confirm, with Touch ID or your password.")
        #expect(absent.pairingToken == nil)
    }

    @Test func aPairedMachineRequestsOverTheNetwork() async throws {
        #expect(try await mayi(["list", "--remote"], environment: machine).status == 69, "not paired yet")

        #expect(await model.startPairing(acl: AclRecord(all: true, tags: [], secrets: [])) == nil)
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

    /// A machine paired with only a tag gets the secrets carrying it, is
    /// refused the rest without a prompt, and lists only what it may use.
    @Test func aMachineUsesOnlyWhatItsAclAllows() async throws {
        #expect(model.saveSecret(name: "CI_TOKEN", level: 1, values: ["value": "ci"], allow: [], maxGrantSecs: 60, tags: ["ci"]) == nil)
        #expect(model.usableBy(name: "CI_TOKEN", tags: ["ci"]) == ["Agents on test-mac"], "no machine yet")

        #expect(await model.startPairing(acl: AclRecord(all: false, tags: ["ci"], secrets: [])) == nil)
        let token = try #require(model.pairingToken)
        #expect(try await mayi(["pair", token, "--name", "build-vm"], environment: machine).status == 0)
        try await eventually { model.lastPaired == "build-vm" }
        let vm = try #require(model.machines.first { $0.name == "build-vm" })
        #expect(vm.acl == AclRecord(all: false, tags: ["ci"], secrets: []))
        #expect(model.usableBy(name: "CI_TOKEN", tags: ["ci"]) == ["Agents on test-mac", "build-vm"])

        let listed = try await mayi(["list", "--remote"], environment: machine)
        #expect(listed.out.hasPrefix("CI_TOKEN\t") && !listed.out.contains("L1\t"))
        let refused = try await mayi(["run", "--remote", "-s", "L1", "-r", "r", "--", "true"], environment: machine)
        #expect(refused.status == 77)
        #expect(refused.err.contains("L1 is not in this machine's ACL"))
        #expect(model.notices.isEmpty && model.pending.isEmpty, "nobody was asked")

        // Granted by name too, from Machines.
        #expect(model.setMachineAcl(id: vm.id, acl: AclRecord(all: false, tags: ["ci"], secrets: ["L1"])) == nil)
        let allowed = try await mayi(["run", "--remote", "-s", "L1", "-r", "r", "--", "true"], environment: machine)
        #expect(allowed.status == 0)

        // This Mac's agents have an ACL of their own, everything to start with.
        let mac = try #require(model.devices.first { $0.thisDevice })
        #expect(mac.agentsAcl == AclRecord(all: true, tags: [], secrets: []))
    }
}