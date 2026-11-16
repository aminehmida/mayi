import Foundation
import Testing

@testable import MayiKit

/// The whole path a real request takes: the requester CLI, the unix socket,
/// the Rust core, and the app model that the windows are drawn from. Only
/// the windows themselves and the fingerprint sensor are left out.
@MainActor
@Suite(.serialized) struct EndToEndTests {
    let model = AppModel(presence: FixedPresence())
    let keys = TestKeys()
    let socket: String

    init() throws {
        let dir = try scratch()
        socket = dir.appendingPathComponent("s.sock").path
        model.noticeLinger = 0.2
        try model.start(
            keys: keys, paths: MayiPaths(home: dir.appendingPathComponent("home"), socket: socket),
            deviceName: "test")
        for (name, level) in [("L1", UInt8(1)), ("L2", 2), ("L3", 3), ("L4", 4)] {
            #expect(
                model.saveSecret(
                    name: name, level: level, values: ["value": "\(name)-secret-value"], allow: [],
                    maxGrantSecs: 600) == nil)
        }
    }

    private func run(_ secret: String, _ script: String) async throws -> CommandResult {
        try await mayi(["run", "-s", secret, "-r", "end to end test", "--", "sh", "-c", script], socket: socket)
    }

    @Test func listShowsNamesOnly() async throws {
        let result = try await mayi(["list"], socket: socket)
        #expect(result.status == 0)
        #expect(result.out.contains("L4\tlevel 4"))
        #expect(!result.out.contains("secret-value"))
    }

    @Test func levelOneIsSilentAndMasked() async throws {
        let result = try await run("L1", "echo \"v=$L1\"; exit 7")
        #expect(result.status == 7)
        #expect(result.out == "v=[masked]\n")
        #expect(model.pending.isEmpty && model.notices.isEmpty)
        try await eventually { model.log.contains { $0.event == "exit" } }
        let request = try #require(model.log.first { $0.event == "request" })
        #expect(request.outcome == "released" && request.reason == "end to end test")
        #expect(request.session == "test-session")
    }

    @Test func levelTwoShowsANoticeThatCanStopTheCommand() async throws {
        async let result = run("L2", "echo started; sleep 30; echo not-reached")
        try await eventually { !model.notices.isEmpty }
        let notice = model.notices[0]
        #expect(notice.notice.secrets == ["L2"])
        #expect(notice.notice.request.command.hasPrefix("sh -c "))
        model.stop(runId: notice.id)
        #expect(model.notices[0].stopped)
        let finished = try await result
        #expect(finished.status == 143)
        // Stop can land before the shell prints anything, never after the sleep.
        #expect(!finished.out.contains("not-reached"))
        #expect(finished.err.contains("stopped by the user"))
        try await eventually { model.notices.isEmpty }
        try await eventually { model.log.contains { $0.event == "stop" } }
    }

    @Test func levelThreeWaitsForTheUser() async throws {
        async let denied = run("L3", "echo $L3")
        try await eventually { model.pending.count == 1 }
        let prompt = model.pending[0].prompt
        #expect(prompt.secrets.map(\.name) == ["L3"] && prompt.secrets[0].needsApproval)
        #expect(prompt.request.command == "sh -c 'echo $L3'")
        #expect(prompt.request.reason == "end to end test" && !prompt.request.remote)
        model.answer(model.pending[0].id, .deny)
        let deniedResult = try await denied
        #expect(deniedResult.status == 77)
        #expect(deniedResult.err.contains("denied by the user"))

        async let allowed = run("L3", "echo $L3")
        try await eventually { model.pending.count == 1 }
        model.answer(model.pending[0].id, .sessionCommand)
        #expect(try await allowed.out == "[masked]\n")

        // The session grant covers the same command, and only that one.
        #expect(try await run("L3", "echo $L3").status == 0)
        #expect(model.pending.isEmpty)
        async let other = run("L3", "echo other $L3")
        try await eventually { model.pending.count == 1 }
        model.answer(model.pending[0].id, .deny)
        #expect(try await other.status == 77)
    }

    @Test func levelFourNeedsTheBiometricKey() async throws {
        keys.allowBiometric = false
        let refused = try await run("L4", "echo $L4")
        #expect(refused.status == 77)
        #expect(refused.err.contains("biometric check failed"))

        keys.allowBiometric = true
        let allowed = try await run("L4", "echo \"${#L4} $L4\"")
        #expect(allowed.out == "15 [masked]\n")
        #expect(keys.prompts.last == "Unlock L4 for `sh -c 'echo \"${#L4} $L4\"'` on local")
        #expect(model.pending.isEmpty, "the biometric check is the approval")

        // Within the window the same command needs no second check.
        let count = keys.prompts.count
        #expect(try await run("L4", "echo \"${#L4} $L4\"").status == 0)
        #expect(keys.prompts.count == count)
    }

    @Test func aPromptIsWithdrawnWhenTheRequesterGivesUp() async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: cliPath())
        process.arguments = ["run", "-s", "L3", "-r", "about to be interrupted", "--", "true"]
        process.environment = ["MAYI_SOCKET": socket]
        process.standardInput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        try await eventually { model.pending.count == 1 }
        process.terminate()
        try await eventually { model.pending.isEmpty }
        try await eventually { model.log.last?.outcome == "denied: the requester went away" }
    }

    @Test func aPromptNobodyAnswersIsDenied() async throws {
        // Reach the bridge through a fresh model with a short timeout.
        let dir = try scratch()
        let quick = AppModel(presence: FixedPresence())
        let path = dir.appendingPathComponent("s.sock").path
        try quick.start(
            keys: TestKeys(), paths: MayiPaths(home: dir.appendingPathComponent("home"), socket: path),
            deviceName: "test", approvalTimeout: 0.5)
        _ = quick.saveSecret(name: "L3", level: 3, values: ["value": "some-secret"], allow: [], maxGrantSecs: 0)
        let result = try await mayi(
            ["run", "-s", "L3", "-r", "nobody home", "--", "true"], socket: path)
        #expect(result.status == 77)
        try await eventually { quick.pending.isEmpty }
    }

    @Test func valuesAreShownOnlyToTheOwnerAndLogged() async throws {
        let dir = try scratch()
        let paths = MayiPaths(home: dir.appendingPathComponent("home"), socket: dir.appendingPathComponent("s.sock").path)
        let away = AppModel(presence: FixedPresence(present: false))
        try away.start(keys: TestKeys(), paths: paths, deviceName: "test")
        _ = away.saveSecret(name: "TOKEN", level: 3, values: ["value": "abc123"], allow: [], maxGrantSecs: 0)
        let secret = try #require(away.secrets.first)
        #expect(secret.copies == 1, "a vault on one device holds one copy")
        guard case .failure = await away.revealSecret(secret) else {
            Issue.record("shown without the owner")
            return
        }

        let dir2 = try scratch()
        let owner = AppModel(presence: FixedPresence())
        try owner.start(
            keys: TestKeys(),
            paths: MayiPaths(home: dir2.appendingPathComponent("home"), socket: dir2.appendingPathComponent("s.sock").path),
            deviceName: "test")
        _ = owner.saveSecret(name: "TOKEN", level: 3, values: ["value": "abc123"], allow: [], maxGrantSecs: 0)
        let revealed = try await owner.revealSecret(try #require(owner.secrets.first)).get()
        #expect(revealed.fields.map(\.value) == ["abc123"])
        #expect(owner.log.last?.event == "view")
    }

    @Test func theOwnerIsAskedOnceUntilTheMacLocks() async throws {
        let dir = try scratch()
        let presence = CountingPresence()
        let model = AppModel(presence: presence)
        try model.start(
            keys: TestKeys(),
            paths: MayiPaths(home: dir.appendingPathComponent("home"), socket: dir.appendingPathComponent("s.sock").path),
            deviceName: "test")
        _ = model.saveSecret(name: "A", level: 2, values: ["value": "a"], allow: [], maxGrantSecs: 0)
        _ = model.saveSecret(name: "B", level: 3, values: ["value": "b"], allow: [], maxGrantSecs: 0)
        #expect(!model.unlocked)
        for secret in model.secrets {
            _ = try await model.revealSecret(secret).get()
        }
        #expect(await model.startPairing() == nil)
        #expect(presence.count == 1, "one confirmation covers every value and the pairing")
        model.lock()
        _ = try await model.revealSecret(try #require(model.secrets.first)).get()
        #expect(presence.count == 2, "locked again: asked again")
    }
}
