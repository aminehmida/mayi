package dev.mayi.android

import dev.mayi.ffi.AclRecord
import dev.mayi.ffi.ApprovalChoice
import dev.mayi.ffi.AuditRecord
import dev.mayi.ffi.AwsAccountRecord
import dev.mayi.ffi.AwsProfileRecord
import dev.mayi.ffi.AwsSession
import dev.mayi.ffi.AwsSignInFlow
import dev.mayi.ffi.AwsSignInNeededInfo
import dev.mayi.ffi.DeviceInfo
import dev.mayi.ffi.KeyStore
import dev.mayi.ffi.MachineRecord
import dev.mayi.ffi.MayiException
import dev.mayi.ffi.NoticeInfo
import dev.mayi.ffi.PromptInfo
import dev.mayi.ffi.RevealedSecret
import dev.mayi.ffi.SecretRecord
import dev.mayi.ffi.UiDelegate
import dev.mayi.ffi.VaultDevice
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Everything the screens show, and the answers they give back to the Rust
 * core. Free of Android classes so it can be tested on a desktop JVM against
 * the real core.
 */
class MayiController(
    /**
     * A prompt nobody answers is denied after this long. The requester
     * usually gives up first, which takes the prompt down.
     */
    private val approvalTimeoutMs: Long = 3_600_000,
    /** How long a notice stays visible after its command ended. */
    private val noticeLingerMs: Long = 4_000,
    /** Whether the owner is using the phone right now. */
    private val userActive: () -> Boolean = { false },
    /** A machine just connected. */
    private val onIncoming: () -> Unit = {},
) : UiDelegate {
    data class ActiveNotice(val notice: NoticeInfo, val ended: Boolean = false, val stopped: Boolean = false)

    data class State(
        val pending: List<PromptInfo> = emptyList(),
        /** Requests waiting while the owner signs in to AWS again. */
        val signIns: List<AwsSignInNeededInfo> = emptyList(),
        val notices: List<ActiveNotice> = emptyList(),
        val secrets: List<SecretRecord> = emptyList(),
        val devices: List<DeviceInfo> = emptyList(),
        val machines: List<MachineRecord> = emptyList(),
        val log: List<AuditRecord> = emptyList(),
        val syncStatus: String? = null,
        /** The machine that most recently finished pairing. */
        val lastPaired: String? = null,
        /** The device that most recently joined. */
        val lastDeviceAdded: String? = null,
    )

    @Volatile
    var state = State()
        private set

    @Volatile
    var device: VaultDevice? = null
        private set

    private val listeners = CopyOnWriteArrayList<(State) -> Unit>()
    private val answers = ConcurrentHashMap<ULong, CompletableFuture<ApprovalChoice>>()
    private val signInAnswers = ConcurrentHashMap<ULong, CompletableFuture<Boolean>>()
    private val timer = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "mayi-timer").apply { isDaemon = true } }

    fun observe(listener: (State) -> Unit) = listeners.add(listener)

    fun unobserve(listener: (State) -> Unit) = listeners.remove(listener)

    @Synchronized
    private fun update(change: (State) -> State) {
        state = change(state)
        listeners.forEach { it(state) }
    }

    /** Opens the vault at [vaultPath], creating it on first run. */
    @Throws(MayiException::class)
    fun open(vaultPath: String, deviceName: String, keys: KeyStore) {
        device = VaultDevice.open(vaultPath, deviceName, keys, this)
        refresh()
    }

    /** Starts accepting paired machines and other devices; returns the port. */
    @Throws(MayiException::class)
    fun listen(port: UShort, addresses: List<String> = emptyList()): UShort =
        checkNotNull(device) { "the vault is not open" }.serveRemote(port, addresses)

    /** Publishes where this phone is again; returns whether that changed. */
    fun republish(): Boolean = runCatching { device?.republish() ?: false }.getOrDefault(false)

    // --- Called by the core, on its own threads ------------------------------

    override fun approve(prompt: PromptInfo): ApprovalChoice {
        val answer = CompletableFuture<ApprovalChoice>()
        answers[prompt.runId] = answer
        update { it.copy(pending = it.pending + prompt) }
        try {
            return answer.get(approvalTimeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            return ApprovalChoice.DENY
        } finally {
            answers.remove(prompt.runId)
            update { s -> s.copy(pending = s.pending.filter { it.runId != prompt.runId }) }
        }
    }

    override fun withdraw(runId: ULong) {
        answers[runId]?.complete(ApprovalChoice.DENY)
        signInAnswers[runId]?.complete(false)
    }

    override fun notify(notice: NoticeInfo) {
        update { it.copy(notices = it.notices + ActiveNotice(notice)) }
    }

    override fun finished(runId: ULong, exitCode: Int?) {
        update { s -> s.copy(notices = s.notices.map { if (it.notice.runId == runId) it.copy(ended = true) else it }) }
        timer.schedule({ dismiss(runId) }, noticeLingerMs, TimeUnit.MILLISECONDS)
    }

    override fun paired(name: String, id: String) {
        update { it.copy(lastPaired = name) }
        refresh()
    }

    override fun deviceAdded(name: String) {
        update { it.copy(lastDeviceAdded = name) }
        refresh()
    }

    override fun synced(changed: ULong) = refresh()

    override fun logged() = refresh()

    override fun userActive(): Boolean = userActive.invoke()

    override fun incoming() = onIncoming()

    /**
     * An AWS sign-in ended while a request needed it: shows it on the
     * Requests tab and waits while the owner signs in again
     * ([beginAwsSignIn], [finishAwsSignIn], [renewAwsSignIn]), then
     * [answerSignIn]. The request carries on if they did.
     */
    override fun signInNeeded(needed: AwsSignInNeededInfo): Boolean {
        val answer = CompletableFuture<Boolean>()
        signInAnswers[needed.runId] = answer
        update { it.copy(signIns = it.signIns + needed) }
        try {
            return answer.get(approvalTimeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            return false
        } finally {
            signInAnswers.remove(needed.runId)
            update { s -> s.copy(signIns = s.signIns.filter { it.runId != needed.runId }) }
            timer.schedule({ refresh() }, 300, TimeUnit.MILLISECONDS)
        }
    }

    // --- Called by the screens ------------------------------------------------

    fun answer(runId: ULong, choice: ApprovalChoice) {
        answers[runId]?.complete(choice)
    }

    /** The owner signed in to AWS again for a waiting request, or gave up. */
    fun answerSignIn(runId: ULong, signedIn: Boolean) {
        signInAnswers[runId]?.complete(signedIn)
    }

    // --- AWS sign-ins: each blocks on the network, so call off the main thread

    private fun <T> network(action: () -> T): Result<T> = try {
        Result.success(action())
    } catch (e: MayiException) {
        Result.failure(IllegalStateException(describe(e)))
    }

    /** Starts signing in to an AWS portal: open [AwsSignInFlow.verificationUrl] in the browser. */
    fun beginAwsSignIn(startUrl: String, region: String): Result<AwsSignInFlow> =
        network { AwsSignInFlow.start(startUrl.trim(), region.trim()) }

    /** Waits until the owner allows the sign-in in the browser. */
    fun finishAwsSignIn(flow: AwsSignInFlow): Result<AwsSession> = network { flow.`wait`() }

    /** The accounts and roles a new sign-in reaches. */
    fun awsAccounts(session: AwsSession): Result<List<AwsAccountRecord>> = network { session.accounts() }

    /** The accounts and roles a saved sign-in reaches, to add profiles. */
    fun awsAccounts(name: String): Result<List<AwsAccountRecord>> =
        result { it.awsAccounts(name) }

    /** Saves a new AWS sign-in offering [profiles]. Returns an error message on failure. */
    fun saveAwsSignIn(name: String, session: AwsSession, profiles: List<AwsProfileRecord>, tags: List<String>): String? =
        attempt { it.putAwsSignIn(name.trim(), session, profiles, tags) }

    /** Keeps the new session after signing in to a saved sign-in again. */
    fun renewAwsSignIn(name: String, session: AwsSession): String? = attempt { it.renewAwsSignIn(name, session) }

    /** Changes a sign-in's profiles: adding one or lowering a level asks for a fingerprint. */
    fun updateAwsProfiles(name: String, profiles: List<AwsProfileRecord>): String? =
        attempt { it.updateAwsProfiles(name, profiles) }

    /**
     * A secret's values, for its owner to see. Confirm they are present first;
     * a level 4 secret asks for a fingerprint itself. Blocks. Logged as viewed.
     */
    fun reveal(name: String): Result<RevealedSecret> =
        runCatching { checkNotNull(device) { "the vault is not open" }.revealSecret(name, "Show $name") }
            .also { refresh() }

    /** Kills the command of a released run and revokes its session. */
    fun stop(runId: ULong) {
        if (device?.stop(runId) == true) {
            update { s -> s.copy(notices = s.notices.map { if (it.notice.runId == runId) it.copy(stopped = true) else it }) }
        }
    }

    fun dismiss(runId: ULong) {
        update { s -> s.copy(notices = s.notices.filter { it.notice.runId != runId }) }
    }

    fun refresh() {
        val device = device ?: return
        try {
            val secrets = device.listSecrets()
            val devices = device.devices()
            val machines = device.machines()
            val log = device.auditTail(200u)
            update { it.copy(secrets = secrets, devices = devices, machines = machines, log = log) }
        } catch (e: MayiException) {
            update { it.copy(syncStatus = describe(e)) }
        }
    }

    /** Creates or replaces a secret. Returns an error message on failure. */
    fun saveSecret(
        name: String, level: UByte, values: Map<String, String>, allow: List<String>, maxGrantSecs: ULong,
        login: Boolean = false, sites: List<String> = emptyList(), tags: List<String> = emptyList(),
    ): String? = attempt { it.putSecret(name, level, values, allow, maxGrantSecs, login, sites, tags) }

    /** Changes a secret's expected commands, websites, grant cap and tags, keeping its values. */
    fun updateRules(
        name: String, allow: List<String>, maxGrantSecs: ULong, sites: List<String>, tags: List<String> = emptyList(),
    ): String? = attempt { it.updateRules(name, allow, maxGrantSecs, sites, tags) }

    /** Drops the note that a secret should be replaced, once the owner checked it needs no replacing. */
    fun dismissRotation(name: String): String? = attempt { it.dismissRotation(name) }

    fun deleteSecret(name: String): String? = attempt { it.removeSecret(name) }

    private fun <T> result(action: (VaultDevice) -> T): Result<T> {
        val device = device ?: return Result.failure(IllegalStateException("The vault is not open."))
        return try {
            val value = action(device)
            refresh()
            Result.success(value)
        } catch (e: MayiException) {
            Result.failure(IllegalStateException(describe(e)))
        }
    }

    /**
     * An invitation for a machine to pair (`mayi pair TOKEN` there), valid for
     * [ttlSecs]. The machine may use only what [acl] allows.
     */
    fun startPairing(ttlSecs: ULong, acl: AclRecord): Result<String> {
        update { it.copy(lastPaired = null) }
        return result { it.startPairing(emptyList(), ttlSecs, acl) }
    }

    /** Changes which secrets a paired machine, or the agents behind it, may use. */
    fun setMachineAcl(id: String, acl: AclRecord): String? = attempt { it.setMachineAcl(id, acl) }

    /** Changes which secrets the agents on a vault device may use. */
    fun setAgentsAcl(deviceId: String, acl: AclRecord): String? = attempt { it.setAgentsAcl(deviceId, acl) }

    /** Who could use a secret with these tags: "Agents on …" and paired machines. */
    fun usableBy(name: String, tags: List<String>): List<String> =
        runCatching { device?.usableBy(name, tags) }.getOrNull() ?: emptyList()

    /** An invitation for a new device to scan or paste, valid for [ttlSecs]. */
    fun startEnrolment(ttlSecs: ULong): Result<String> {
        update { it.copy(lastDeviceAdded = null) }
        return result { it.startEnrolment(emptyList(), ttlSecs) }
    }

    fun cancelInvitation() {
        device?.cancelPairing()
    }

    /** Removes a device; returns the secrets it could read, to rotate. */
    fun removeDevice(id: String): Result<List<String>> = result { it.removeDevice(id) }

    /** Creates the offline recovery key, shown once. Blocks: may ask for a fingerprint. */
    fun createRecoveryKey(): Result<String> =
        result { it.createRecoveryKey("Share level 4 secrets with the recovery key") }

    /** Whether the vault holds nothing yet, so joining another one loses nothing. */
    val vaultIsEmpty: Boolean
        get() = state.secrets.isEmpty() && state.machines.none { !it.revoked } &&
            state.devices.none { !it.thisDevice && !it.removed }

    fun revokeMachine(id: String): String? = attempt { it.revokeMachine(id) }

    /**
     * Adds the device that shows [code], the code a new device shows while it
     * has no vault. It receives the whole vault; a fingerprint is asked for if
     * level 4 keys must be shared. Blocks: call off the main thread. Returns
     * the new device's name.
     */
    fun addDevice(code: String): Result<String> {
        val device = device ?: return Result.failure(IllegalStateException("The vault is not open."))
        return try {
            val name = device.addDeviceByCode(code.trim())
            refresh()
            Result.success(name)
        } catch (e: MayiException) {
            Result.failure(IllegalStateException(describe(e)))
        }
    }

    private fun attempt(action: (VaultDevice) -> Unit): String? {
        val device = device ?: return "The vault is not open."
        return try {
            action(device)
            refresh()
            null
        } catch (e: MayiException) {
            describe(e)
        }
    }

    /** Syncs with the vault's other devices. Blocks; call off the main thread. */
    fun sync() {
        val device = device ?: return
        // Where this phone is now goes out with the sync.
        runCatching { device.republish() }
        val status = try {
            device.syncAll().joinToString("  ·  ") { r -> "${r.device}: ${r.error ?: "up to date"}" }
        } catch (e: MayiException) {
            describe(e)
        }
        update { it.copy(syncStatus = status.ifEmpty { null }) }
        refresh()
    }

    companion object {
        fun describe(e: Throwable): String = when (e) {
            is MayiException.Failed -> e.detail
            else -> e.message ?: e.toString()
        }
    }
}
