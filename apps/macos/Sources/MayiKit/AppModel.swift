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
    private var syncTimer: Timer?

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

    /// Opens (or creates) the vault and starts serving requesters.
    ///
    /// A prompt nobody answers within `approvalTimeout` seconds is denied.
    public func start(
        keys: KeyStore, paths: MayiPaths, deviceName: String, approvalTimeout: TimeInterval = 300
    ) throws {
        try FileManager.default.createDirectory(
            at: paths.home, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let bridge = UiBridge(model: self, approvalTimeout: approvalTimeout)
        let device = try VaultDevice.open(
            vaultPath: paths.vault.path, deviceName: deviceName, keys: keys, ui: bridge)
        try device.serve(socketPath: paths.socket)
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

    private var hasOtherDevices: Bool { devices.contains { !$0.thisDevice && !$0.removed && !$0.recovery } }

    /// Opens an invitation for a new vault device after the user proves they
    /// are present. Returns an error message on failure.
    public func startEnrolment() async -> String? {
        guard let device, let paths else { return "The vault is not open." }
        guard await presence.confirm(reason: "add a device that will hold all your secrets") else {
            return "Adding a device needs your fingerprint."
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
        guard await presence.confirm(reason: "create a key that can open your vault without this Mac") else {
            return "Creating a recovery key needs your fingerprint."
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
            _ = try device.serveRemote(port: paths.port, addresses: paths.advertise, wake: nil)
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
        guard await presence.confirm(reason: "allow another machine to request secrets") else {
            return "Pairing needs your fingerprint."
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
}
