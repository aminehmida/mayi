package dev.mayi.android

import dev.mayi.ffi.ApprovalChoice
import dev.mayi.ffi.AuditRecord
import dev.mayi.ffi.DeviceInfo
import dev.mayi.ffi.KeyStore
import dev.mayi.ffi.MachineRecord
import dev.mayi.ffi.MayiException
import dev.mayi.ffi.NoticeInfo
import dev.mayi.ffi.PromptInfo
import dev.mayi.ffi.SecretRecord
import dev.mayi.ffi.UiDelegate
import dev.mayi.ffi.VaultDevice
import dev.mayi.ffi.WakeInfo
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
    /** A prompt nobody answers is denied after this long. */
    private val approvalTimeoutMs: Long = 300_000,
    /** How long a notice stays visible after its command ended. */
    private val noticeLingerMs: Long = 4_000,
) : UiDelegate {
    data class ActiveNotice(val notice: NoticeInfo, val ended: Boolean = false, val stopped: Boolean = false)

    data class State(
        val pending: List<PromptInfo> = emptyList(),
        val notices: List<ActiveNotice> = emptyList(),
        val secrets: List<SecretRecord> = emptyList(),
        val devices: List<DeviceInfo> = emptyList(),
        val machines: List<MachineRecord> = emptyList(),
        val log: List<AuditRecord> = emptyList(),
        val syncStatus: String? = null,
    )

    @Volatile
    var state = State()
        private set

    @Volatile
    var device: VaultDevice? = null
        private set

    private val listeners = CopyOnWriteArrayList<(State) -> Unit>()
    private val answers = ConcurrentHashMap<ULong, CompletableFuture<ApprovalChoice>>()
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
    fun listen(port: UShort, addresses: List<String> = emptyList(), wake: WakeInfo? = null): UShort =
        checkNotNull(device) { "the vault is not open" }.serveRemote(port, addresses, wake)

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
            timer.schedule({ refresh() }, 300, TimeUnit.MILLISECONDS)
        }
    }

    override fun withdraw(runId: ULong) {
        answers[runId]?.complete(ApprovalChoice.DENY)
    }

    override fun notify(notice: NoticeInfo) {
        update { it.copy(notices = it.notices + ActiveNotice(notice)) }
    }

    override fun finished(runId: ULong, exitCode: Int?) {
        update { s -> s.copy(notices = s.notices.map { if (it.notice.runId == runId) it.copy(ended = true) else it }) }
        timer.schedule({ dismiss(runId); refresh() }, noticeLingerMs, TimeUnit.MILLISECONDS)
    }

    override fun paired(name: String, id: String) = refresh()

    override fun deviceAdded(name: String) = refresh()

    override fun synced(changed: ULong) = refresh()

    // --- Called by the screens ------------------------------------------------

    fun answer(runId: ULong, choice: ApprovalChoice) {
        answers[runId]?.complete(choice)
    }

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
        login: Boolean = false, sites: List<String> = emptyList(),
    ): String? = attempt { it.putSecret(name, level, values, allow, maxGrantSecs, login, sites) }

    fun deleteSecret(name: String): String? = attempt { it.removeSecret(name) }

    fun revokeMachine(id: String): String? = attempt { it.revokeMachine(id) }

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
