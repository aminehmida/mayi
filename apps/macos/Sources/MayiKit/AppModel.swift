import AppKit
import CoreGraphics
import Foundation
import Network

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

    /// A request waiting while the owner signs in to AWS again.
    public struct PendingSignIn: Identifiable {
        public let id: UUID
        public let needed: AwsSignInNeededInfo
        let complete: (Bool) -> Void
    }

    public struct ActiveNotice: Identifiable {
        public var id: UInt64 { notice.runId }
        public let notice: NoticeInfo
        /// The command ended or was stopped; the notice is about to go away.
        public var ended = false
        public var stopped = false
    }

    @Published public private(set) var pending: [PendingApproval] = []
    @Published public private(set) var pendingSignIns: [PendingSignIn] = []
    /// Whether Mayi keeps an AWS CLI profile for each AWS profile in
    /// ~/.aws/config, so `aws --profile`, Terraform and SDKs ask Mayi.
    @Published public private(set) var awsCliProfiles: Bool =
        UserDefaults.standard.object(forKey: "awsCliProfiles") as? Bool ?? true
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
    private var pathMonitor: NWPathMonitor?
    private var networkSettled: DispatchWorkItem?

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
        // This Mac serves agents: they get an ACL, of every secret at first.
        _ = try? device.agentsAcl()
        try? device.setLocalEnrol(allowed: localEnrol)
        self.bridge = bridge
        self.device = device
        self.paths = paths
        socketPath = paths.socket
        refresh()
        // The profiles in ~/.aws/config run the `mayi` inside this app: keep
        // them pointing at the copy running now, after an update or a move.
        writeAwsCliProfiles()
        // The network port is opened only once there is someone to serve.
        if machines.contains(where: { !$0.revoked }) || hasOtherDevices {
            listenForMachines()
        }
        if hasOtherDevices {
            syncNow()
        }
        watchNetwork()
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
            // Where this Mac is now goes out with the sync.
            _ = try? device.republish()
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

    /// Tells the other devices where this Mac is after a network change (a
    /// new Wi-Fi, Ethernet, a VPN such as Tailscale coming up), once the
    /// burst of changes has settled.
    private func watchNetwork() {
        guard pathMonitor == nil else { return }
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] _ in
            DispatchQueue.main.async { MainActor.assumeIsolated { self?.networkChanged() } }
        }
        monitor.start(queue: .global(qos: .utility))
        pathMonitor = monitor
    }

    private func networkChanged() {
        networkSettled?.cancel()
        let settled = DispatchWorkItem { [weak self] in
            MainActor.assumeIsolated {
                guard let self, let device = self.device else { return }
                if (try? device.republish()) == true { self.syncNow() }
            }
        }
        networkSettled = settled
        DispatchQueue.main.asyncAfter(deadline: .now() + 2, execute: settled)
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
    /// Opens an invitation for a machine that may use the secrets `acl`
    /// allows once paired.
    public func startPairing(acl: AclRecord) async -> String? {
        guard let device, let paths else { return "The vault is not open." }
        guard await unlock() else {
            return "Pairing needs you to confirm, with Touch ID or your password."
        }
        guard listenForMachines() else { return remoteError }
        do {
            lastPaired = nil
            pairingToken = try device.startPairing(
                addresses: paths.advertise, ttlSecs: Self.pairingMinutes * 60, acl: acl)
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
    }

    /// Nobody answered in time; the prompt is no longer answerable.
    func expire(_ id: UUID) {
        pending.removeAll { $0.id == id }
    }

    /// The requester went away: take its prompt down.
    func withdraw(runId: UInt64) {
        if let index = pendingSignIns.firstIndex(where: { $0.needed.runId == runId }) {
            pendingSignIns.remove(at: index).complete(false)
        }
        guard let index = pending.firstIndex(where: { $0.prompt.runId == runId }) else { return }
        pending.remove(at: index).complete(.deny)
    }

    func enqueueSignIn(id: UUID, needed: AwsSignInNeededInfo, complete: @escaping (Bool) -> Void) {
        pendingSignIns.append(PendingSignIn(id: id, needed: needed, complete: complete))
    }

    /// The owner signed in again (or gave up) for a waiting request.
    public func answerSignIn(_ id: UUID, signedIn: Bool) {
        guard let index = pendingSignIns.firstIndex(where: { $0.id == id }) else { return }
        pendingSignIns.remove(at: index).complete(signedIn)
    }

    func expireSignIn(_ id: UUID) {
        pendingSignIns.removeAll { $0.id == id }
    }

    // MARK: Notices

    func show(_ notice: NoticeInfo) {
        notices.append(ActiveNotice(notice: notice))
    }

    func finished(runId: UInt64) {
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

    /// Creates or replaces a secret or a login. Returns an error message on failure.
    public func saveSecret(
        name: String, level: UInt8, values: [String: String], allow: [String], maxGrantSecs: UInt64,
        login: Bool = false, sites: [String] = [], tags: [String] = []
    ) -> String? {
        guard let device else { return "The vault is not open." }
        do {
            _ = try device.putSecret(
                name: name, level: level, values: values, allow: allow, maxGrantSecs: maxGrantSecs, login: login,
                sites: sites, tags: tags)
            refresh()
            syncNow()
            return nil
        } catch {
            return describe(error)
        }
    }

    /// Saves an edit from the secret editor. Off the main thread: lowering a
    /// level, or adding an expected command or website, asks for Touch ID.
    public func save(_ change: SecretDraft.Change) async -> String? {
        guard let device else { return "The vault is not open." }
        let problem = await Task.detached { () -> String? in
            do {
                switch change {
                case .put(let name, let level, let values, let allow, let maxGrantSecs, let login, let sites, let tags):
                    _ = try device.putSecret(
                        name: name, level: level, values: values, allow: allow, maxGrantSecs: maxGrantSecs,
                        login: login, sites: sites, tags: tags)
                case .rules(let name, let allow, let maxGrantSecs, let sites, let tags):
                    _ = try device.updateRules(
                        name: name, allow: allow, maxGrantSecs: maxGrantSecs, sites: sites, tags: tags)
                }
                return nil
            } catch {
                return describe(error)
            }
        }.value
        refresh()
        if problem == nil { syncNow() }
        return problem
    }

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

    /// Changes the allowed commands or websites, the approval lifetime and
    /// the tags, keeping the values.
    public func updateRules(
        name: String, allow: [String], maxGrantSecs: UInt64, sites: [String] = [], tags: [String] = []
    ) -> String? {
        guard let device else { return "The vault is not open." }
        do {
            _ = try device.updateRules(
                name: name, allow: allow, maxGrantSecs: maxGrantSecs, sites: sites, tags: tags)
            refresh()
            syncNow()
            return nil
        } catch {
            return describe(error)
        }
    }

    /// The owner decided a secret flagged for rotation needs none.
    public func dismissRotation(name: String) -> String? {
        guard let device else { return "The vault is not open." }
        do {
            _ = try device.dismissRotation(name: name)
            refresh()
            syncNow()
            return nil
        } catch {
            return describe(error)
        }
    }

    // MARK: AWS sign-ins

    /// Portals the AWS CLI on this Mac already knows, to suggest.
    public func knownAwsPortals() -> [AwsPortalRecord] { awsKnownPortals() }

    nonisolated private static func failure(_ error: Error) -> DraftError { DraftError(stringLiteral: describe(error)) }

    /// Starts signing in to an AWS portal: register with AWS, then the owner
    /// approves in the browser (`AwsSignInFlow.verificationUrl`).
    public func beginAwsSignIn(startUrl: String, region: String) async -> Result<AwsSignInFlow, DraftError> {
        await Task.detached { () -> Result<AwsSignInFlow, DraftError> in
            do { return .success(try AwsSignInFlow.start(startUrl: startUrl, region: region)) } catch {
                return .failure(Self.failure(error))
            }
        }.value
    }

    /// Waits for the owner to allow the sign-in in the browser.
    public func finishAwsSignIn(_ flow: AwsSignInFlow) async -> Result<AwsSession, DraftError> {
        await Task.detached { () -> Result<AwsSession, DraftError> in
            do { return .success(try flow.wait()) } catch { return .failure(Self.failure(error)) }
        }.value
    }

    /// The accounts and roles a new sign-in reaches.
    public func awsAccounts(_ session: AwsSession) async -> Result<[AwsAccountRecord], DraftError> {
        await Task.detached { () -> Result<[AwsAccountRecord], DraftError> in
            do { return .success(try session.accounts()) } catch { return .failure(Self.failure(error)) }
        }.value
    }

    /// The accounts and roles a saved sign-in reaches, to add profiles.
    public func awsAccounts(name: String) async -> Result<[AwsAccountRecord], DraftError> {
        guard let device else { return .failure("The vault is not open.") }
        return await Task.detached { () -> Result<[AwsAccountRecord], DraftError> in
            do { return .success(try device.awsAccounts(name: name)) } catch { return .failure(Self.failure(error)) }
        }.value
    }

    /// Saves a new AWS sign-in. Then removes the AWS CLI's own saved
    /// sign-in to the same portal, which any program could read, if asked.
    public func saveAwsSignIn(
        name: String, session: AwsSession, profiles: [AwsProfileRecord], tags: [String], forgetCliSignIns: Bool
    ) async -> String? {
        guard let device else { return "The vault is not open." }
        let startUrl = session.startUrl()
        let problem = await Task.detached { () -> String? in
            do {
                _ = try device.putAwsSignIn(name: name, session: session, profiles: profiles, tags: tags)
                if forgetCliSignIns { _ = try? awsForgetCliSignIns(startUrl: startUrl) }
                return nil
            } catch {
                return describe(error)
            }
        }.value
        awsChanged(problem)
        return problem
    }

    /// Changes a sign-in's profiles. Adding one or lowering a level asks for
    /// Touch ID first, which is why this runs off the main thread.
    public func updateAwsProfiles(name: String, profiles: [AwsProfileRecord]) async -> String? {
        guard let device else { return "The vault is not open." }
        let problem = await Task.detached { () -> String? in
            do {
                _ = try device.updateAwsProfiles(name: name, profiles: profiles)
                return nil
            } catch {
                return describe(error)
            }
        }.value
        awsChanged(problem)
        return problem
    }

    /// Keeps the new session after signing in to a saved sign-in again.
    public func renewAwsSignIn(name: String, session: AwsSession) async -> String? {
        guard let device else { return "The vault is not open." }
        let problem = await Task.detached { () -> String? in
            do {
                _ = try device.renewAwsSignIn(name: name, session: session)
                return nil
            } catch {
                return describe(error)
            }
        }.value
        awsChanged(problem)
        return problem
    }

    /// Removes the AWS CLI's saved sign-in to a portal from this Mac.
    public func forgetAwsCliSignIns(startUrl: String) -> String? {
        do {
            _ = try awsForgetCliSignIns(startUrl: startUrl)
            refresh()
            return nil
        } catch {
            return describe(error)
        }
    }

    public func setAwsCliProfiles(_ on: Bool) {
        awsCliProfiles = on
        UserDefaults.standard.set(on, forKey: "awsCliProfiles")
        writeAwsCliProfiles()
    }

    private func awsChanged(_ problem: String?) {
        refresh()
        guard problem == nil else { return }
        syncNow()
        writeAwsCliProfiles()
    }

    /// The `mayi` the AWS CLI profiles run: the one inside this app, whose
    /// path survives updates.
    private var mayiPath: String {
        Bundle.main.url(forResource: "mayi", withExtension: nil)?.path ?? "/opt/homebrew/bin/mayi"
    }

    /// Keeps ~/.aws/config in step with the AWS profiles, when the owner
    /// wants that, and removes Mayi's part when not.
    private func writeAwsCliProfiles() {
        guard let device, secrets.contains(where: { $0.aws != nil }) || !awsCliProfiles else { return }
        let path = mayiPath
        let include = awsCliProfiles
        Task.detached { _ = try? device.writeAwsCliProfiles(mayiPath: path, include: include) }
    }

    /// The tags in use, sorted.
    public var tags: [String] {
        Array(Set(secrets.flatMap(\.tags))).sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }

    // MARK: ACLs

    /// Who could use a secret with this name and these tags: the machines
    /// and the devices' agents whose ACL allows it.
    public func usableBy(name: String, tags: [String]) -> [String] {
        (try? device?.usableBy(name: name, tags: tags)) ?? []
    }

    /// Changes which secrets a machine may use.
    public func setMachineAcl(id: String, acl: AclRecord) -> String? {
        guard let device else { return "The vault is not open." }
        do {
            try device.setMachineAcl(id: id, acl: acl)
            refresh()
            syncNow()
            return nil
        } catch {
            return describe(error)
        }
    }

    /// Changes which secrets the agents on a device's machine may use.
    public func setAgentsAcl(deviceId: String, acl: AclRecord) -> String? {
        guard let device else { return "The vault is not open." }
        do {
            try device.setAgentsAcl(deviceId: deviceId, acl: acl)
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

    func logged() {
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

    /// Shows "sign in to AWS again" with the request, and waits while the
    /// owner does it (or gives up).
    func signInNeeded(needed: AwsSignInNeededInfo) -> Bool {
        let id = UUID()
        let done = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var signedIn = false
        DispatchQueue.main.async { [model] in
            MainActor.assumeIsolated {
                guard let model else {
                    done.signal()
                    return
                }
                model.enqueueSignIn(id: id, needed: needed) { answer in
                    lock.withLock { signedIn = answer }
                    done.signal()
                }
            }
        }
        if done.wait(timeout: .now() + approvalTimeout) == .timedOut {
            DispatchQueue.main.async { [model] in MainActor.assumeIsolated { model?.expireSignIn(id) } }
            return false
        }
        return lock.withLock { signedIn }
    }
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
