package dev.mayi.android

import android.app.AlarmManager
import android.app.Application
import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import dev.mayi.ffi.JoinInvitation
import dev.mayi.ffi.joinVault
import java.io.File
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

private const val CHANNEL_SERVICE = "service"
private const val CHANNEL_REQUESTS = "requests"
private const val NOTE_SERVICE = 1
private const val NOTE_ATTENTION = 2
/** An intent extra: open on the Requests tab. */
const val EXTRA_OPEN_REQUESTS = "dev.mayi.android.OPEN_REQUESTS"

/** Port paired machines and other devices connect to. */
private const val PORT: UShort = 7462u

/** How often the restart check runs. */
private const val RESTART_CHECK_MS = 15 * 60 * 1000L

/** Makers whose battery savers are known to stop apps that Android itself keeps. */
private val strictMakers = setOf("samsung", "xiaomi", "oneplus", "huawei", "honor", "oppo", "vivo", "realme", "meizu", "asus", "sony")

class MayiApp : Application() {
    val controller = MayiController(userActive = { userActive() }, onIncoming = { stayAwakeBriefly() })

    /** The activity on screen, if any: where a fingerprint prompt can be shown. */
    @Volatile
    var foreground: MainActivity? = null

    /** Emulators have no secure hardware; a debug build may still be tried on one. */
    private val onEmulator: Boolean
        get() = Build.HARDWARE == "ranchu" || Build.HARDWARE == "goldfish" || Build.FINGERPRINT.contains("generic")

    private val keys: KeystoreKeys by lazy {
        KeystoreKeys(allowSoftwareKeys = BuildConfig.DEBUG && onEmulator, authenticate = ::authenticate)
    }
    private val vaultFile: File get() = File(filesDir, "vault.db")

    val hasVault: Boolean get() = vaultFile.exists()

    val defaultDeviceName: String
        get() = Settings.Global.getString(contentResolver, Settings.Global.DEVICE_NAME) ?: Build.MODEL

    /**
     * The owner confirmed with a fingerprint since the screen last locked, so
     * showing values, pairing and the like ask nothing more. Level 4 secrets
     * still ask on every use.
     */
    @Volatile
    var unlocked = false
        private set

    /** When the app last went to the background, or 0 while it is on screen. */
    @Volatile
    var backgroundSince = 0L

    /** Asks for a fingerprint once, then stays unlocked until [lock]. Blocks. */
    @Synchronized
    fun unlock(reason: String = "Unlock Mayi"): Boolean {
        if (!unlocked) unlocked = authenticate(reason)
        return unlocked
    }

    fun lock() {
        unlocked = false
    }

    /** Whether this phone can hold a vault at all: it needs a strong biometric. */
    val biometricsReady: Boolean
        get() = BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    /**
     * Whether Android leaves Mayi running while the phone sleeps (battery use
     * "Unrestricted"). Without it, requests may not reach the phone, and the
     * restart check cannot bring the service back.
     */
    val backgroundAllowed: Boolean
        get() = getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(packageName)

    /** Shows Android's dialog that lets Mayi run in the background. */
    fun askToRunInBackground(context: Context) {
        context.startActivity(
            Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))
    }

    /** For phones whose maker stops apps anyway: the page that says what else to turn off. */
    val makerHelpPage: String?
        get() = Build.MANUFACTURER.lowercase().takeIf { it in strictMakers }?.let { "https://dontkillmyapp.com/$it" }

    /** The phone is unlocked and its screen on: its owner is using it. */
    private fun userActive(): Boolean =
        getSystemService(PowerManager::class.java).isInteractive &&
            !getSystemService(KeyguardManager::class.java).isKeyguardLocked

    private val wakeLock by lazy {
        getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "mayi:incoming")
            .apply { setReferenceCounted(false) }
    }

    /** A machine connected: stay awake long enough for its request to arrive and be shown. */
    private fun stayAwakeBriefly() = wakeLock.acquire(30_000)

    /**
     * Every 15 minutes, starts the service again if Android stopped it.
     * Android allows that while Mayi may run in the background. Rescheduling
     * replaces the earlier alarm.
     */
    fun scheduleRestartCheck() {
        val check = PendingIntent.getBroadcast(
            this, 0, Intent(this, RestartCheck::class.java), PendingIntent.FLAG_IMMUTABLE)
        getSystemService(AlarmManager::class.java).setInexactRepeating(
            AlarmManager.ELAPSED_REALTIME_WAKEUP, SystemClock.elapsedRealtime() + RESTART_CHECK_MS, RESTART_CHECK_MS, check)
    }

    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_SERVICE, "Vault availability", NotificationManager.IMPORTANCE_MIN))
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_REQUESTS, "Requests needing you", NotificationManager.IMPORTANCE_HIGH))
        controller.observe { state ->
            if (state.pending.isNotEmpty() && foreground == null) {
                alert("An agent is waiting for your approval")
            } else if (state.signIns.isNotEmpty() && foreground == null) {
                alert("Sign in to ${state.signIns.first().name} again: a command is waiting")
            } else if (state.pending.isEmpty() && state.signIns.isEmpty()) {
                manager.cancel(NOTE_ATTENTION)
            }
        }
        // The service is not started here: the process may be starting in the
        // background, where Android refuses a foreground service. It is started
        // by the screen, the boot receiver and the restart check instead.
        if (hasVault) scheduleRestartCheck()
        // Locks when the screen goes off.
        ContextCompat.registerReceiver(
            this,
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) = lock()
            },
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    /**
     * Keeps the vault serving, if there is one. Only allowed while the app is
     * on screen, just after boot, or while Mayi may run in the background;
     * elsewhere it does nothing.
     */
    fun ensureServing() {
        if (!hasVault) return
        try {
            startService()
        } catch (e: IllegalStateException) {
            // ForegroundServiceStartNotAllowedException: not allowed from here.
        }
    }

    private fun startService() {
        ContextCompat.startForegroundService(this, Intent(this, VaultService::class.java))
    }

    /** Opens the vault and starts serving. Safe to call more than once. */
    @Synchronized
    fun open(): String? = try {
        if (controller.device == null) {
            controller.open(vaultFile.path, defaultDeviceName, keys)
        }
        publish()
        scheduleRestartCheck()
        null
    } catch (e: Exception) {
        MayiController.describe(e)
    }

    private fun publish() {
        controller.listen(PORT)
        Thread { controller.sync() }.start()
        watchNetwork()
    }

    private val settle = Handler(Looper.getMainLooper())
    private var watchingNetwork = false

    /**
     * Tells the other devices where this phone is after a network change (a
     * new Wi-Fi, mobile data, a VPN such as Tailscale coming up), once the
     * burst of changes has settled.
     */
    @Synchronized
    private fun watchNetwork() {
        if (watchingNetwork) return
        watchingNetwork = true
        val changed = Runnable { Thread { if (controller.republish()) controller.sync() }.start() }
        val callback = object : ConnectivityManager.NetworkCallback() {
            private fun soon() {
                settle.removeCallbacks(changed)
                settle.postDelayed(changed, 2_000)
            }
            override fun onAvailable(network: Network) = soon()
            override fun onLost(network: Network) = soon()
            override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) = soon()
        }
        // VPNs included: a plain request leaves them out.
        val everything = NetworkRequest.Builder().removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build()
        getSystemService(ConnectivityManager::class.java).registerNetworkCallback(everything, callback)
    }

    /** Creates a new vault on this phone. Returns an error message on failure. */
    fun createVault(): String? = open().also { if (it == null) startService() }

    /** Joins the vault of another device with its enrolment token. Blocks. */
    fun join(token: String): String? = try {
        joinVault(vaultFile.path, defaultDeviceName, keys, token.trim())
        open().also { if (it == null) startService() }
    } catch (e: Exception) {
        MayiController.describe(e)
    }

    /** A code for a device that holds the vault to scan or paste, valid ten minutes. */
    fun openJoinCode(): JoinInvitation = JoinInvitation.open(emptyList(), 600u)

    /**
     * Waits until a device with the vault adds this phone through [code],
     * then opens the vault. Blocks. Returns an error message, or null.
     */
    fun joinByCode(code: JoinInvitation): String? = try {
        code.wait(vaultFile.path, defaultDeviceName, keys)
        open().also { if (it == null) startService() }
    } catch (e: Exception) {
        MayiController.describe(e)
    }

    /** Whether requests that arrive in the background can reach the user. */
    val notificationsBlocked: Boolean
        get() {
            val manager = NotificationManagerCompat.from(this)
            val channel = manager.getNotificationChannel(CHANNEL_REQUESTS)
            return !manager.areNotificationsEnabled() || channel?.importance == NotificationManager.IMPORTANCE_NONE
        }

    /**
     * Moves this phone's empty vault aside and restarts the app into setup,
     * to join another vault. The file is kept, renamed. Returns an error
     * message if the vault is not empty.
     */
    fun setAsideEmptyVault(activity: android.app.Activity): String? {
        if (!controller.vaultIsEmpty) return "This vault holds secrets or other devices, so Mayi will not replace it."
        val stamp = java.text.SimpleDateFormat("yyyyMMdd-HHmmss", java.util.Locale.ROOT).format(java.util.Date())
        filesDir.listFiles { f -> f.name == "vault.db" || f.name.startsWith("vault.db-") }?.forEach {
            it.renameTo(File(filesDir, "set-aside-$stamp-${it.name}"))
        }
        stopService(Intent(this, VaultService::class.java))
        // The core keeps its port open until the process ends, so start afresh.
        activity.startActivity(
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK))
        Runtime.getRuntime().exit(0)
        return null
    }

    /**
     * Shows the fingerprint prompt and waits for the result. Called on the
     * core's threads. If the app is not on screen, asks for attention with a
     * notification and waits for the user to open it.
     */
    fun authenticate(reason: String): Boolean {
        if (foreground == null) alert(reason)
        val deadline = System.currentTimeMillis() + 60_000
        while (foreground == null && System.currentTimeMillis() < deadline) Thread.sleep(200)
        val activity = foreground ?: return false
        val result = CompletableFuture<Boolean>()
        activity.runOnUiThread {
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                    result.complete(true)
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    result.complete(false)
                }
            }
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Mayi")
                .setSubtitle(reason)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText("Cancel")
                .build()
            BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback).authenticate(info)
        }
        getSystemService(NotificationManager::class.java).cancel(NOTE_ATTENTION)
        return try {
            result.get(120, TimeUnit.SECONDS)
        } catch (e: Exception) {
            false
        }
    }

    private fun openAppIntent(): PendingIntent = PendingIntent.getActivity(
        this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)

    /** Opens the app on its Requests tab, where the waiting request is. */
    private fun openRequestsIntent(): PendingIntent = PendingIntent.getActivity(
        this, 1, Intent(this, MainActivity::class.java).putExtra(EXTRA_OPEN_REQUESTS, true),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)

    private fun alert(text: String) {
        val notification = Notification.Builder(this, CHANNEL_REQUESTS)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle("Mayi")
            .setContentText(text)
            .setContentIntent(openRequestsIntent())
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(NOTE_ATTENTION, notification)
    }

    fun serviceNotification(): Notification = Notification.Builder(this, CHANNEL_SERVICE)
        .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
        .setContentTitle("Mayi is ready to answer requests")
        .setContentIntent(openAppIntent())
        .setOngoing(true)
        .build()
}

/** Keeps the process alive and the vault reachable while the phone is awake. */
class VaultService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val app = application as MayiApp
        startForeground(NOTE_SERVICE, app.serviceNotification())
        Thread { app.open() }.start()
        return START_STICKY
    }
}

/** After a restart, serves again without waiting for the app to be opened. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        (context.applicationContext as MayiApp).ensureServing()
    }
}

/** Brings the service back if Android stopped it; see [MayiApp.scheduleRestartCheck]. */
class RestartCheck : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        (context.applicationContext as MayiApp).ensureServing()
    }
}
