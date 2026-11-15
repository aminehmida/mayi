package dev.mayi.android

import android.app.Application
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import dev.mayi.ffi.JoinInvitation
import dev.mayi.ffi.WakeInfo
import dev.mayi.ffi.joinVault
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import org.json.JSONObject

private const val CHANNEL_SERVICE = "service"
private const val CHANNEL_REQUESTS = "requests"
private const val NOTE_SERVICE = 1
private const val NOTE_ATTENTION = 2

/** Port paired machines and other devices connect to. */
private const val PORT: UShort = 7462u

class MayiApp : Application() {
    val controller = MayiController()

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
    private val prefs get() = getSharedPreferences("mayi", Context.MODE_PRIVATE)

    val hasVault: Boolean get() = vaultFile.exists()

    val defaultDeviceName: String
        get() = Settings.Global.getString(contentResolver, Settings.Global.DEVICE_NAME) ?: Build.MODEL

    /** Whether this phone can hold a vault at all: it needs a strong biometric. */
    val biometricsReady: Boolean
        get() = BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

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
            } else if (state.pending.isEmpty()) {
                manager.cancel(NOTE_ATTENTION)
            }
        }
        // The service is not started here: the process may be starting in the
        // background, where Android refuses a foreground service. It is started
        // by the screen, the boot receiver and the wake-up push instead.
    }

    /**
     * Keeps the vault serving, if there is one. Only allowed while the app is
     * on screen, just after boot, or on a wake-up push; elsewhere it does nothing.
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
        registerForWakeUps()
        null
    } catch (e: Exception) {
        MayiController.describe(e)
    }

    private fun publish() {
        val wake = prefs.getString("wake_id", null)
            ?.takeIf { BuildConfig.WAKE_URL.isNotEmpty() }
            ?.let { WakeInfo("${BuildConfig.WAKE_URL}/wake", it) }
        controller.listen(PORT, emptyList(), wake)
        Thread { controller.sync() }.start()
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

    private fun alert(text: String) {
        val notification = Notification.Builder(this, CHANNEL_REQUESTS)
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentTitle("Mayi")
            .setContentText(text)
            .setContentIntent(openAppIntent())
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

    // --- Wake-up pushes -------------------------------------------------------
    // Optional: needs a Firebase project (google-services.json) and a deployed
    // gateway (mayi.wakeUrl). Without them the phone answers only while awake.

    private fun registerForWakeUps() {
        if (BuildConfig.WAKE_URL.isEmpty() || FirebaseApp.getApps(this).isEmpty()) return
        FirebaseMessaging.getInstance().token.addOnSuccessListener { registerWake(it) }
    }

    /** Exchanges the push token for a wake id that machines can use. */
    fun registerWake(pushToken: String) {
        if (BuildConfig.WAKE_URL.isEmpty() || prefs.getString("push_token", null) == pushToken) return
        Thread {
            try {
                val connection = URL("${BuildConfig.WAKE_URL}/register").openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.doOutput = true
                connection.setRequestProperty("content-type", "application/json")
                connection.outputStream.use { it.write(JSONObject().put("token", pushToken).toString().toByteArray()) }
                val id = JSONObject(connection.inputStream.bufferedReader().readText()).getString("id")
                prefs.edit().putString("push_token", pushToken).putString("wake_id", id).apply()
                if (controller.device != null) publish()
            } catch (e: Exception) {
                // Tried again the next time the app starts.
            }
        }.start()
    }
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

/** The empty wake-up push: all it has to do is bring the service up. */
class WakeService : FirebaseMessagingService() {
    override fun onMessageReceived(message: RemoteMessage) {
        (application as MayiApp).ensureServing()
    }

    override fun onNewToken(token: String) {
        (application as MayiApp).registerWake(token)
    }
}
