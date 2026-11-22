import AppKit
import CryptoKit
import Foundation
import SwiftUI

@testable import MayiKit

/// In-memory keys with a switch standing in for the fingerprint sensor.
final class TestKeys: KeyStore, @unchecked Sendable {
    let device = P256.KeyAgreement.PrivateKey()
    let biometric = P256.KeyAgreement.PrivateKey()
    private let lock = NSLock()
    private var _allowBiometric = true
    private var _prompts: [String] = []

    var allowBiometric: Bool {
        get { lock.withLock { _allowBiometric } }
        set { lock.withLock { _allowBiometric = newValue } }
    }
    var prompts: [String] { lock.withLock { _prompts } }

    func devicePublic() -> Data { device.publicKey.x963Representation }
    func biometricPublic() -> Data { biometric.publicKey.x963Representation }

    private func agree(_ key: P256.KeyAgreement.PrivateKey, _ peer: Data) throws -> Data {
        try key.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: peer))
            .withUnsafeBytes { Data($0) }
    }

    func deviceEcdh(peerPublic: Data) throws -> Data {
        try agree(device, peerPublic)
    }

    func cancelBiometric() {}

    func biometricEcdh(peerPublics: [Data], prompt: String) throws -> [Data] {
        lock.withLock { _prompts.append(prompt) }
        guard allowBiometric else { throw KeyError.Denied }
        return try peerPublics.map { try agree(biometric, $0) }
    }
}

final class SilentUi: UiDelegate, @unchecked Sendable {
    func approve(prompt: PromptInfo) -> ApprovalChoice { .deny }
    func withdraw(runId: UInt64) {}
    func notify(notice: NoticeInfo) {}
    func paired(name: String, id: String) {}
    func deviceAdded(name: String) {}
    func synced(changed: UInt64) {}
    func finished(runId: UInt64, exitCode: Int32?) {}
    func userActive() -> Bool { false }
    func incoming() {}
    func signInNeeded(needed: AwsSignInNeededInfo) -> Bool { false }
}

/// A scratch directory short enough for a unix socket path.
func scratch() throws -> URL {
    let dir = URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("mayi-\(UUID().uuidString.prefix(8))")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

/// Stands in for the fingerprint check before pairing.
struct FixedPresence: PresenceCheck {
    var present = true
    func confirm(reason: String) async -> Bool { present }
}

/// Counts how often the owner is asked, and always says yes.
final class CountingPresence: PresenceCheck, @unchecked Sendable {
    private let lock = NSLock()
    private var asked = 0
    var count: Int { lock.withLock { asked } }
    func confirm(reason: String) async -> Bool {
        lock.withLock { asked += 1 }
        return true
    }
}

struct CommandResult {
    var status: Int32
    var out: String
    var err: String
}

func cliPath() -> String {
    ProcessInfo.processInfo.environment["MAYI_CLI"]
        ?? URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("target/release/mayi").path
}

/// Runs the real requester CLI against `socket`.
func mayi(_ arguments: [String], socket: String) async throws -> CommandResult {
    try await mayi(arguments, environment: ["MAYI_SOCKET": socket])
}

/// Runs the real requester CLI with extra environment variables.
func mayi(_ arguments: [String], environment extra: [String: String]) async throws -> CommandResult {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: cliPath())
    process.arguments = arguments
    var environment = ProcessInfo.processInfo.environment
    environment["MAYI_SESSION"] = "test-session"
    environment.merge(extra) { _, new in new }
    process.environment = environment
    process.standardInput = FileHandle.nullDevice
    let (out, err) = (Pipe(), Pipe())
    process.standardOutput = out
    process.standardError = err
    return try await withCheckedThrowingContinuation { continuation in
        process.terminationHandler = { finished in
            let read = { (pipe: Pipe) in
                String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            }
            continuation.resume(
                returning: CommandResult(status: finished.terminationStatus, out: read(out), err: read(err)))
        }
        do {
            try process.run()
        } catch {
            continuation.resume(throwing: error)
        }
    }
}

/// Waits until `condition` holds on the main actor, or fails after `timeout`.
@MainActor
func eventually(timeout: TimeInterval = 10, _ condition: () -> Bool) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while !condition() {
        if Date() > deadline { throw TimedOut() }
        try await Task.sleep(nanoseconds: 20_000_000)
    }
}

struct TimedOut: Error {}

private typealias CreateWindowImage = @convention(c) (CGRect, UInt32, UInt32, UInt32) -> Unmanaged<CGImage>?

/// Captures a real window of this process, chrome and materials included,
/// to a PNG in $MAYI_SNAPSHOT_DIR. A process may photograph its own windows
/// without screen-recording permission; the call is looked up at run time
/// because newer SDKs no longer declare it.
@MainActor
func capture(_ window: NSWindow, name: String, dark: Bool) async throws {
    guard let dir = ProcessInfo.processInfo.environment["MAYI_SNAPSHOT_DIR"],
        let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "CGWindowListCreateImage")
    else { return }
    window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
    window.orderFrontRegardless()
    try await Task.sleep(nanoseconds: 900_000_000)
    let createImage = unsafeBitCast(symbol, to: CreateWindowImage.self)
    // Including only this window (8), without its shadow (1).
    guard let image = createImage(.null, 8, UInt32(window.windowNumber), 1)?.takeRetainedValue(),
        let png = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])
    else { return }
    try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    try png.write(to: URL(fileURLWithPath: dir).appendingPathComponent("\(name).png"))
}

/// Renders a view to a PNG in $MAYI_SNAPSHOT_DIR, for looking at the UI
/// without clicking through the app. Does nothing when the variable is unset.
@MainActor
func snapshot<V: View>(_ view: V, name: String, dark: Bool = true) async throws {
    guard let dir = ProcessInfo.processInfo.environment["MAYI_SNAPSHOT_DIR"] else { return }
    _ = NSApplication.shared
    let hosting = NSHostingView(rootView: view)
    hosting.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
    let window = NSWindow(
        contentRect: NSRect(origin: .zero, size: hosting.fittingSize),
        styleMask: [.borderless], backing: .buffered, defer: false)
    window.contentView = hosting
    try await Task.sleep(nanoseconds: 300_000_000)
    hosting.layoutSubtreeIfNeeded()
    guard let bitmap = hosting.bitmapImageRepForCachingDisplay(in: hosting.bounds) else { return }
    hosting.cacheDisplay(in: hosting.bounds, to: bitmap)
    guard let png = bitmap.representation(using: .png, properties: [:]) else { return }
    try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    try png.write(to: URL(fileURLWithPath: dir).appendingPathComponent("\(name).png"))
}
