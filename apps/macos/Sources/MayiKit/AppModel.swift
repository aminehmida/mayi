import AppKit
import CoreGraphics
import Foundation

/// Where the app keeps its files. Overridable through the environment so
/// tests and experiments never touch the real vault.
public struct MayiPaths {
    public var home: URL
    public var socket: String
    /// TCP port paired machines connect to; 0 picks a free one.
    public var port: UInt16
    /// Addresses to put in pairing tokens; empty means this Mac's own.
    public var advertise: [String]

    public var vault: URL { home.appendingPathComponent("vault.db") }
    public var keys: URL { home.appendingPathComponent("keys") }

    public init(home: URL, socket: String, port: UInt16 = 7462, advertise: [String] = []) {
        self.home = home
        self.socket = socket
        self.port = port
        self.advertise = advertise
    }

    public static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) -> MayiPaths {
        let fm = FileManager.default
        let home =
            env["MAYI_APP_HOME"].map { URL(fileURLWithPath: $0) }
            ?? fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Mayi")
        // The requester CLI looks for the socket here by default.
        let socket =
            env["MAYI_SOCKET"]
            ?? fm.homeDirectoryForCurrentUser.appendingPathComponent(".mayi/mayi.sock").path
        return MayiPaths(
            home: home, socket: socket,
            port: env["MAYI_PORT"].flatMap { UInt16($0) } ?? 7462,
            advertise: env["MAYI_ADVERTISE"]?.split(separator: ",").map(String.init) ?? [])
    }
}

extension MayiError {
    public var message: String {
        switch self {
        case .Failed(let message): return message
        }
    }
}

func describe(_ error: Error) -> String {
    (error as? MayiError)?.message ?? error.localizedDescription
}

/// Everything the windows show. Lives on the main thread; the Rust core
/// reaches it through `UiBridge`.
@MainActor
public final class AppModel: ObservableObject {
    public struct PendingApproval: Identifiable {
        public let id: UUID
        public let prompt: PromptInfo
        let complete: (ApprovalChoice) -> Void
    }

    public struct ActiveNotice: Identifiable {
        public var id: UInt64 { notice.runId }
        public let notice: NoticeInfo
        /// The command ended or was stopped; the notice is about to go away.
        public var ended = false
        public var stopped = false
    }

    @Published public private(set) var pending: [PendingApproval] = []
    @Published public private(set) var notices: [ActiveNotice] = []
    @Published public private(set) var secrets: [SecretRecord] = []
    @Published public private(set) var log: [AuditRecord] = []
    @Published public private(set) var socketPath: String?
    @Published public private(set) var machines: [MachineRecord] = []
    /// The open pairing invitation, if any.
    @Published public private(set) var pairingToken: String?
    /// Name of the machine that most recently finished pairing.
    @Published public private(set) var lastPaired: String?
    /// Why other machines cannot connect, if they cannot.
    @Published public private(set) var remoteError: String?
    @Published public private(set) var devices: [DeviceInfo] = []
    /// The open invitation for a new vault device, if any.
    @Published public private(set) var enrolmentToken: String?
    /// Name of the device that most recently joined.
    @Published public private(set) var lastDeviceAdded: String?
    /// Outcome of the last sync, for display.
    @Published public private(set) var syncStatus: String?
    /// What to rotate after removing a device or revoking a machine.
    @Published public var rotationAdvice: String?
    /// A recovery key just created, shown once and then forgotten.
    @Published public private(set) var recoveryKey: String?
    /// The owner confirmed with Touch ID or their password since the Mac was
    /// last locked or asleep, so showing values, pairing and the like need
    /// no further check. Level 4 secrets still ask on every use.
    @Published public private(set) var unlocked = false
    private var syncTimer: Timer?
    private var lockWatchers: [NSObjectProtocol] = []

    /// How often to sync with the vault's other devices while running.
    public static let syncInterval: TimeInterval = 300

    /// How long a pairing invitation stays open.
    public static let pairingMinutes: UInt64 = 10

    /// How long a notice stays visible after its command ended.
    public var noticeLinger: TimeInterval = 4

    public private(set) var device: VaultDevice?
    private var bridge: UiBridge?
    private var paths: MayiPaths?
    private let presence: PresenceCheck

    public init(presence: PresenceCheck = BiometricPresence()) {
        self.presence = presence
    }

    /// Asks the owner once, then keeps Mayi unlocked until the Mac locks or
    /// sleeps. Returns whether it is unlocked.
    @discardableResult
    public func unlock(reason: String = "show your secrets and manage your devices") async -> Bool {
        if unlocked { return true }
        guard await presence.confirm(reason: reason) else { return false }
        unlocked = true
        watchForLock()
        return true
    }

    public func lock() {
        unlocked = false
    }

    /// Locks Mayi when the screen locks, the display sleeps or the Mac sleeps.
    private func watchForLock() {
        guard lockWatchers.isEmpty else { return }
        let relock: @Sendable (Notification) -> Void = { [weak self] _ in
            DispatchQueue.main.async { MainActor.assumeIsolated { self?.lock() } }
        }
        let workspace = NSWorkspace.shared.notificationCenter
        for name in [
            NSWorkspace.screensDidSleepNotification, NSWorkspace.willSleepNotification,
            NSWorkspace.sessionDidResignActiveNotification,
        ] {
            lockWatchers.append(workspace.addObserver(forName: name, object: nil, queue: nil, using: relock))
        }
        lockWatchers.append(
            DistributedNotificationCenter.default().addObserver(
                forName: .init("com.apple.screenIsLocked"), object: nil, queue: nil, using: relock))
    }

    /// Opens (or creates) the vault and starts serving requesters.
    ///
    /// A prompt nobody answers within `approvalTimeout` seconds is denied;
    /// the requester usually gives up first, which takes the prompt down.
    public func start(
        keys: KeyStore, paths: MayiPaths, deviceName: String, approvalTimeout: TimeInterval = 3600
    ) throws {
        try FileManager.default.createDirectory(
            at: paths.home, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let bridge = UiBridge(model: self, approvalTimeout: approvalTimeout)
        let device = try VaultDevice.open(
            vaultPath: paths.vault.path, deviceName: deviceName, keys: keys, ui: bridge)
        try device.serve(socketPath: paths.socket)
        try? device.setLocalEnrol(allowed: localEnrol)
        self.bridge = bridge
        self.device = device
        self.paths = paths
        socketPath = paths.socket
        refresh()
        // The network port is opened only once there is someone to serve.
        if machines.contains(where: { !$0.revoked }) || hasOtherDevices {
            listenForMachines()
        }
        if hasOtherDevices {
            syncNow()
        }
        syncTimer = Timer.scheduledTimer(withTimeInterval: Self.syncInterval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.syncNow() }
        }
    }

    // MARK: Other devices of the vault

    public var hasOtherDevices: Bool { devices.contains { !$0.thisDevice && !$0.removed && !$0.recovery } }

    /// Whether `mayi` on this Mac may pair itself with the vault, so agents
    /// here can also ask the other devices, such as a phone when you are away.
    @Published public private(set) var localEnrol: Bool =
        UserDefaults.standard.object(forKey: "localEnrol") as? Bool ?? true

    public func setLocalEnrol(_ allowed: Bool) {
        localEnrol = allowed
        UserDefaults.standard.set(allowed, forKey: "localEnrol")
        guard let device else { return }
        // Turning it off revokes the pairing and tells the other devices.
        Task.detached {
            try? device.setLocalEnrol(allowed: allowed)
            await MainActor.run { self.refresh() }
        }
    }

    /// Asked to restart the app, after the vault was set aside to join another.
    public var onRestart: (() -> Void)?

    /// Whether this Mac's vault holds nothing yet, so joining another vault
    /// instead loses nothing.
    public var vaultIsEmpty: Bool {
        secrets.isEmpty && !machines.contains { !$0.revoked } && !hasOtherDevices
            && !devices.contains { $0.recovery && !$0.removed }
    }

    /// Moves this Mac's empty vault aside, so that the next launch offers to
    /// join another. The file is kept, renamed, next to where it was.
    public func setAsideEmptyVault() -> String? {
        guard let paths else { return "The vault is not open." }
        guard vaultIsEmpty else { return "This vault holds secrets or other devices, so Mayi will not replace it." }
        let format = DateFormatter()
        format.dateFormat = "yyyyMMdd-HHmmss"
        let stamp = format.string(from: Date())
        let fm = FileManager.default
        do {
            for name in try fm.contentsOfDirectory(atPath: paths.home.path)
            where name == "vault.db" || name.hasPrefix("vault.db-") {
                try fm.moveItem(
                    at: paths.home.appendingPathComponent(name),
                    to: paths.home.appendingPathComponent("set-aside-\(stamp)-\(name)"))
            }
            return nil
        } catch {
            return describe(error)
        }
    }

    /// Adds the device that shows `code` (the code a new device shows while
    /// it has no vault). It receives the whole vault; Touch ID is asked for
    /// if level 4 keys must be shared with it.
    public func addDevice(code: String) async -> String? {
        guard let device else { return "The vault is not open." }
        let code = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !code.isEmpty else { return "Paste the code the new device shows." }
        do {
            let name = try await Task.detached { try device.addDeviceByCode(code: code) }.value
            deviceAdded(name: name)
            return nil
        } catch {
            return describe(error)
        }
    }

    /// Opens an invitation for a new vault device after the user proves they
    /// are present. Returns an error message on failure.
    public func startEnrolment() async -> String? {
        guard let device, let paths else { return "The vault is not open." }
        guard await unlock() else {
            return "Adding a device needs you to confirm, with Touch ID or your password."
        }
        guard listenForMachines() else { return remoteError }
        do {
            lastDeviceAdded = nil
            enrolmentToken = try device.startEnrolment(
                addresses: paths.advertise, ttlSecs: Self.pairingMinutes * 60)
            return nil
        } catch {
            return describe(error)
        }
    }

    public func cancelEnrolment() {
        device?.cancelPairing()
        enrolmentToken = nil
    }

    func deviceAdded(name: String) {
        enrolmentToken = nil
        lastDeviceAdded = name
        refresh()
    }

    static func advice(_ names: [String], _ what: String) -> String {
        names.isEmpty
            ? "Nothing to rotate: \(what) no secret."
            : "Rotate these secrets, which \(what): \(names.joined(separator: ", "))."
    }

    /// Creates the offline recovery key after the user proves they are
    /// present. The key lands in `recoveryKey`; returns an error message on
    /// failure.
    public func createRecoveryKey() async -> String? {
        guard let device else { return "The vault is not open." }
        guard await unlock() else {
            return "Creating a recovery key needs you to confirm, with Touch ID or your password."
        }
        do {
            // Off the main thread: sharing level 4 keys may ask for Touch ID.
            recoveryKey = try await Task.detached {
                try device.createRecoveryKey(prompt: "Share level 4 secrets with the recovery key")
            }.value
            refresh()
            syncNow()
            return nil
        } catch {
            return describe(error)
        }
    }

    public func forgetRecoveryKey() {
        recoveryKey = nil
    }

    public func removeDevice(id: String) -> String? {
        guard let device else { return "The vault is not open." }
        do {
            let name = devices.first { $0.id == id }?.name ?? "it"
            rotationAdvice = Self.advice(try device.removeDevice(id: id), "\(name) could read")
            refresh()
            syncNow()
            return nil
        } catch {
            return describe(error)
        }
    }

    /// Syncs with the other devices in the background and reports in `syncStatus`.
    public func syncNow() {
        guard let device, hasOtherDevices else { return }
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let summary: String
            do {
                summary = try device.syncAll().map { result in
                    if let error = result.error { return "\(result.device): \(error)" }
                    return "\(result.device): up to date"
                }.joined(separator: "  ·  ")
            } catch {
                summary = describe(error)
            }
            DispatchQueue.main.async {
                MainActor.assumeIsolated {
                    self?.syncStatus = summary
                    self?.refresh()
                }
            }
        }
    }

    // MARK: Other machines

    @discardableResult
    private func listenForMachines() -> Bool {
        guard let device, let paths else { return false }
        do {
            _ = try device.serveRemote(port: paths.port, addresses: paths.advertise)
            remoteError = nil
            return true
        } catch {
            remoteError = "Other machines cannot connect: \(describe(error))"
            return false
        }
    }

    /// Opens a pairing invitation after the user proves they are present.
    /// Returns an error message on failure.
    public func startPairing() async -> String? {
        guard let device, let paths else { return "The vault is not open." }
        guard await unlock() else {
            return "Pairing needs you to confirm, with Touch ID or your password."
        }
        guard listenForMachines() else { return remoteError }
        do {
            lastPaired = nil
            pairingToken = try device.startPairing(
                addresses: paths.advertise, ttlSecs: Self.pairingMinutes * 60)
            return nil
        } catch {
            return describe(error)
        }
    }

    public func cancelPairing() {
        device?.cancelPairing()
        pairingToken = nil
    }

    func paired(name: String) {
        pairingToken = nil
        lastPaired = name
        refresh()
    }

    public func revokeMachine(id: String) -> String? {
        guard let device else { return "The vault is not open." }
        do {
            let name = machines.first { $0.id == id }?.name ?? "it"
            rotationAdvice = Self.advice(try device.revokeMachine(id: id), "this Mac released to \(name)")
            refresh()
            syncNow()
            return nil
        } catch {
            return describe(error)
        }
    }

    // MARK: Approvals

    func enqueue(id: UUID, prompt: PromptInfo, complete: @escaping (ApprovalChoice) -> Void) {
        pending.append(PendingApproval(id: id, prompt: prompt, complete: complete))
    }

    public func answer(_ id: UUID, _ choice: ApprovalChoice) {
        guard let index = pending.firstIndex(where: { $0.id == id }) else { return }
        pending.remove(at: index).complete(choice)
        refreshLogSoon()
    }

    /// Nobody answered in time; the prompt is no longer answerable.
    func expire(_ id: UUID) {
        pending.removeAll { $0.id == id }
    }

    /// The requester went away: take its prompt down.
    func withdraw(runId: UInt64) {
        guard let index = pending.firstIndex(where: { $0.prompt.runId == runId }) else { return }
        pending.remove(at: index).complete(.deny)
        refreshLogSoon()
    }

    // MARK: Notices

    func show(_ notice: NoticeInfo) {
        notices.append(ActiveNotice(notice: notice))
        refreshLogSoon()
    }

    func finished(runId: UInt64) {
        refreshLogSoon()
        guard let index = notices.firstIndex(where: { $0.id == runId }) else { return }
        notices[index].ended = true
        DispatchQueue.main.asyncAfter(deadline: .now() + noticeLinger) { [weak self] in
            self?.notices.removeAll { $0.id == runId }
        }
    }

    /// Kills the command of a released run and revokes its session.
    public func stop(runId: UInt64) {
        guard let device, device.stop(runId: runId) else { return }
        if let index = notices.firstIndex(where: { $0.id == runId }) {
            notices[index].stopped = true
        }
    }

    public func dismissNotice(runId: UInt64) {
        notices.removeAll { $0.id == runId }
    }

    // MARK: Secrets and log

    public func refresh() {
        guard let device else { return }
        secrets = (try? device.listSecrets()) ?? []
        machines = (try? device.machines()) ?? []
        devices = (try? device.devices()) ?? []
        log = (try? device.auditTail(count: 200)) ?? []
    }

    private func refreshLogSoon() {
        // The core writes the audit entry just after calling back.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in self?.refresh() }
    }

    /// Creates or replaces a secret or a login. Returns an error message on failure.
    public func saveSecret(
        name: String, level: UInt8, values: [String: String], allow: [String], maxGrantSecs: UInt64,
        login: Bool = false, sites: [String] = []
    ) -> String? {
        guard let device else { return "The vault is not open." }
        do {
            _ = try device.putSecret(
                name: name, level: level, values: values, allow: allow, maxGrantSecs: maxGrantSecs, login: login,
                sites: sites)
            refresh()
            syncNow()
            return nil
        } catch {
            return describe(error)
        }
    }

    /// Changes the allowed commands or websites and the approval lifetime, keeping the values.
    /// A secret's values for its owner to see, after Touch ID or the login
    /// password; for a level 4 secret, the check that unlocks it does that.
    /// Logged in Activity.
    public func revealSecret(_ secret: SecretRecord) async -> Result<RevealedSecret, DraftError> {
        guard let device else { return .failure("The vault is not open.") }
        let name = secret.name
        if secret.level < 4 {
            guard await unlock() else {
                return .failure("Showing values needs you to confirm, with Touch ID or your password.")
            }
        }
        let result = await Task.detached { () -> Result<RevealedSecret, DraftError> in
            do {
                return .success(try device.revealSecret(name: name, prompt: "show \(name)"))
            } catch {
                return .failure(DraftError(stringLiteral: describe(error)))
            }
        }.value
        refresh()
        return result
    }

    public func updateRules(name: String, allow: [String], maxGrantSecs: UInt64, sites: [String] = []) -> String? {
        guard let device else { return "The vault is not open." }
        do {
            _ = try device.updateRules(name: name, allow: allow, maxGrantSecs: maxGrantSecs, sites: sites)
            refresh()
            syncNow()
            return nil
        } catch {
            return describe(error)
        }
    }

    public func deleteSecret(name: String) -> String? {
        guard let device else { return "The vault is not open." }
        do {
            try device.removeSecret(name: name)
            refresh()
            syncNow()
            return nil
        } catch {
            return describe(error)
        }
    }
}

/// Receives the core's callbacks on its background threads and hands them to
/// the model on the main thread.
final class UiBridge: UiDelegate, @unchecked Sendable {
    private weak var model: AppModel?
    private let approvalTimeout: TimeInterval

    init(model: AppModel, approvalTimeout: TimeInterval) {
        self.model = model
        self.approvalTimeout = approvalTimeout
    }

    func approve(prompt: PromptInfo) -> ApprovalChoice {
        let id = UUID()
        let done = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var choice = ApprovalChoice.deny
        DispatchQueue.main.async { [model] in
            MainActor.assumeIsolated {
                guard let model else {
                    done.signal()
                    return
                }
                model.enqueue(id: id, prompt: prompt) { answer in
                    lock.withLock { choice = answer }
                    done.signal()
                }
            }
        }
        if done.wait(timeout: .now() + approvalTimeout) == .timedOut {
            DispatchQueue.main.async { [model] in MainActor.assumeIsolated { model?.expire(id) } }
            return .deny
        }
        return lock.withLock { choice }
    }

    func withdraw(runId: UInt64) {
        DispatchQueue.main.async { [model] in MainActor.assumeIsolated { model?.withdraw(runId: runId) } }
    }

    func notify(notice: NoticeInfo) {
        DispatchQueue.main.async { [model] in MainActor.assumeIsolated { model?.show(notice) } }
    }

    func paired(name: String, id: String) {
        DispatchQueue.main.async { [model] in MainActor.assumeIsolated { model?.paired(name: name) } }
    }

    func deviceAdded(name: String) {
        DispatchQueue.main.async { [model] in MainActor.assumeIsolated { model?.deviceAdded(name: name) } }
    }

    func synced(changed: UInt64) {
        DispatchQueue.main.async { [model] in MainActor.assumeIsolated { model?.refresh() } }
    }

    func finished(runId: UInt64, exitCode: Int32?) {
        DispatchQueue.main.async { [model] in MainActor.assumeIsolated { model?.finished(runId: runId) } }
    }

    func userActive() -> Bool {
        UserPresence.isActive()
    }

    /// A Mac does not sleep mid-request the way a phone does.
    func incoming() {}
}

/// Whether someone is at this Mac: the screen is unlocked and there was
/// keyboard, mouse or trackpad input in the last two minutes. Requesters ask
/// the device in use first.
enum UserPresence {
    static func isActive() -> Bool {
        if let session = CGSessionCopyCurrentDictionary() as? [String: Any],
            session["CGSSessionScreenIsLocked"] as? Bool == true
        {
            return false
        }
        let anyInput = CGEventType(rawValue: ~0)!
        return CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: anyInput) < 120
    }
}
