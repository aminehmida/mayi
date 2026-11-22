package dev.mayi.android

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.format.DateUtils
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Sell
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.SuggestionChip
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.Undo
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.outlined.Cancel
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Devices
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.Laptop
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.PhoneAndroid
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material.icons.outlined.StopCircle
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.MutableIntState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.fragment.app.FragmentActivity
import dev.mayi.ffi.AclRecord
import dev.mayi.ffi.ApprovalChoice
import dev.mayi.ffi.AuditRecord
import dev.mayi.ffi.DeviceInfo
import dev.mayi.ffi.JoinInvitation
import dev.mayi.ffi.MachineRecord
import dev.mayi.ffi.PromptInfo
import dev.mayi.ffi.RevealedSecret
import dev.mayi.ffi.SecretRecord
import dev.mayi.ffi.twoFactorCode
import java.text.DateFormat
import java.util.Calendar
import java.util.Date

class MainActivity : FragmentActivity() {
    private val app get() = application as MayiApp
    /** Bumped on every resume, so screens re-check settings changed meanwhile. */
    private val resumes = androidx.compose.runtime.mutableIntStateOf(0)
    /** Bumped when a notification asks to show the Requests tab. */
    private val openRequests = androidx.compose.runtime.mutableIntStateOf(0)
    /** Where a scanned code goes, while the scanner is open. */
    private val scanning = mutableStateOf<((String) -> Unit)?>(null)
    private var scanAfterPermission: ((String) -> Unit)? = null
    private val askCamera = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        val onToken = scanAfterPermission.also { scanAfterPermission = null }
        if (granted) {
            scanning.value = onToken
        } else {
            Toast.makeText(this, "Mayi needs the camera to scan a code. You can enter the code as text instead.", Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        app.opened()
        enableEdgeToEdge()
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        }
        setContent {
            MayiTheme {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    var ready by remember { mutableStateOf(app.hasVault) }
                    var askBackground by remember { mutableStateOf(false) }
                    when {
                        !ready -> Setup(app, ::scan) {
                            askBackground = !app.backgroundAllowed
                            ready = true
                        }
                        askBackground -> BackgroundStep(app, resumes) { askBackground = false }
                        else -> Home(app, ::scan, resumes, openRequests)
                    }
                    scanning.value?.let { onToken ->
                        // A window of its own, so it shows above a sheet it was opened from.
                        Dialog(
                            onDismissRequest = { scanning.value = null },
                            properties = DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false),
                        ) {
                            QrScanner(this@MainActivity, onCode = {
                                scanning.value = null
                                onToken(it)
                            }, onCancel = { scanning.value = null })
                        }
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (intent.getBooleanExtra(EXTRA_OPEN_REQUESTS, false)) {
            scanning.value = null
            openRequests.intValue++
        }
    }

    /** Asked to unlock since coming to the screen, so a cancel is not asked again at once. */
    private var askedToUnlock = false

    override fun onStart() {
        super.onStart()
        // Five minutes in the background locks it, as the screen going off does.
        if (app.backgroundSince != 0L && System.currentTimeMillis() - app.backgroundSince > 5 * 60_000) app.lock()
        app.backgroundSince = 0L
    }

    override fun onResume() {
        super.onResume()
        resumes.intValue++
        app.foreground = this
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        // Asked once on opening, rather than for each value shown or device
        // added; not when a request is waiting, so approving stays one tap.
        // Only once the window has focus: a prompt shown while the lock
        // screen is still going away is cancelled by the system.
        if (hasFocus && app.hasVault && !app.unlocked && !askedToUnlock && app.controller.state.pending.isEmpty()) {
            askedToUnlock = true
            Thread { app.unlock() }.start()
        }
    }

    override fun onStop() {
        app.backgroundSince = System.currentTimeMillis()
        askedToUnlock = false
        super.onStop()
    }

    override fun onPause() {
        app.foreground = null
        super.onPause()
    }

    private fun scan(onToken: (String) -> Unit) {
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            scanning.value = onToken
        } else {
            scanAfterPermission = onToken
            askCamera.launch(Manifest.permission.CAMERA)
        }
    }
}

/** What an empty screen says: what belongs here. */
@Composable
private fun EmptyState(icon: ImageVector, title: String, detail: String) {
    Column(
        Modifier.fillMaxSize().padding(horizontal = 40.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(48.dp))
        Spacer(Modifier.height(16.dp))
        Text(title, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(6.dp))
        Text(
            detail, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

// --- Setup ----------------------------------------------------------------------

@Composable
private fun Setup(app: MayiApp, scan: ((String) -> Unit) -> Unit, onReady: () -> Unit) {
    var token by remember { mutableStateOf("") }
    var pasting by remember { mutableStateOf(false) }
    var showingCode by remember { mutableStateOf(false) }
    var confirmCreate by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val quiet = MaterialTheme.colorScheme.onSurfaceVariant

    fun run(action: () -> String?) {
        busy = true
        Thread {
            val problem = action()
            busy = false
            error = problem
            if (problem == null) onReady()
        }.start()
    }

    Column(
        Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 24.dp).verticalScroll(rememberScrollState()),
    ) {
        Spacer(Modifier.height(64.dp))
        AppIcon(72.dp)
        Spacer(Modifier.height(24.dp))
        Text("Mayi", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        Text(
            "Your agents ask before they use a secret. This phone is where you answer.",
            style = MaterialTheme.typography.bodyLarge,
            color = quiet,
        )
        Spacer(Modifier.height(40.dp))
        if (!app.biometricsReady) {
            Text(
                "This phone needs a fingerprint or face set up as a strong biometric before it can hold a vault. Add one in Settings, then come back.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.error,
            )
            return@Column
        }
        if (showingCode) {
            JoinCodePanel(app, onJoined = onReady, onBack = { showingCode = false })
            return@Column
        }
        Text("Join the vault you already have", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(12.dp))
        Button(
            onClick = {
                scan { scanned ->
                    token = scanned
                    run { app.join(scanned) }
                }
            },
            enabled = !busy,
            modifier = Modifier.fillMaxWidth(),
            contentPadding = ButtonDefaults.ButtonWithIconContentPadding,
        ) {
            Icon(Icons.Outlined.QrCodeScanner, contentDescription = null, modifier = Modifier.size(ButtonDefaults.IconSize))
            Spacer(Modifier.width(ButtonDefaults.IconSpacing))
            Text("Scan code from another device")
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "On a Mac with your vault: Devices, Add a Device. On a phone: Devices, +, Add a device, Show an invitation.",
            style = MaterialTheme.typography.bodySmall, color = quiet,
        )
        Spacer(Modifier.height(16.dp))
        OutlinedButton(onClick = { showingCode = true }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text("Show a code for your other device")
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "For another phone with your vault to scan, or a Mac to paste.",
            style = MaterialTheme.typography.bodySmall, color = quiet,
        )
        Spacer(Modifier.height(16.dp))
        if (pasting) {
            OutlinedTextField(
                token, { token = it }, Modifier.fillMaxWidth(),
                label = { Text("Invitation") }, maxLines = 4,
                textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
            )
            Spacer(Modifier.height(12.dp))
            OutlinedButton(onClick = { run { app.join(token) } }, enabled = !busy && token.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
                Text("Join with this invitation")
            }
        } else {
            OutlinedButton(onClick = { pasting = true }, modifier = Modifier.fillMaxWidth()) { Text("Enter invitation as text") }
        }
        if (busy) {
            Spacer(Modifier.height(12.dp))
            Text("Joining. Your other device may ask for a fingerprint.", style = MaterialTheme.typography.bodySmall, color = quiet)
        }
        error?.let {
            Spacer(Modifier.height(12.dp))
            Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(32.dp))
        TextButton(onClick = { confirmCreate = true }, enabled = !busy, modifier = Modifier.align(Alignment.CenterHorizontally)) {
            Text("No vault yet? Create one on this phone")
        }
        Spacer(Modifier.height(24.dp))
    }
    if (confirmCreate) {
        AlertDialog(
            onDismissRequest = { confirmCreate = false },
            title = { Text("Create a new vault?") },
            text = { Text("If your secrets are on a Mac or another phone, join that vault instead. Two vaults share nothing.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmCreate = false
                    run { app.createVault() }
                }) { Text("Create") }
            },
            dismissButton = { TextButton(onClick = { confirmCreate = false }) { Text("Cancel") } },
        )
    }
}

/**
 * After setup: asks Android to leave Mayi running while the phone sleeps, so
 * requests reach it. Moves on by itself once allowed.
 */
@Composable
private fun BackgroundStep(app: MayiApp, resumes: MutableIntState, onDone: () -> Unit) {
    val context = LocalContext.current
    val allowed = remember(resumes.intValue) { app.backgroundAllowed }
    LaunchedEffect(allowed) { if (allowed) onDone() }
    val quiet = MaterialTheme.colorScheme.onSurfaceVariant
    Column(
        Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 24.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Spacer(Modifier.height(48.dp))
        AppIcon(72.dp)
        Text("Let Mayi answer while your phone sleeps", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Your agents ask this phone over your Wi-Fi or Tailscale. To save battery, Android stops apps in the " +
                "background, and a stopped Mayi cannot hear them. Mayi only listens and never checks in, so " +
                "this costs almost no battery.",
            style = MaterialTheme.typography.bodyLarge, color = quiet,
        )
        Button(onClick = { app.askToRunInBackground(context) }, modifier = Modifier.fillMaxWidth()) {
            Text("Allow in the background")
        }
        app.makerHelpPage?.let { page ->
            Text(
                "Your phone's maker may stop apps even so. dontkillmyapp.com says what else to turn off on this phone.",
                style = MaterialTheme.typography.bodyMedium, color = quiet,
            )
            OutlinedButton(onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(page))) }) {
                Text("What else to turn off")
            }
        }
        Text(
            "Away from home, keep Tailscale connected: in Android's VPN settings, turn on Always-on VPN for Tailscale.",
            style = MaterialTheme.typography.bodySmall, color = quiet,
        )
        TextButton(onClick = onDone, modifier = Modifier.align(Alignment.CenterHorizontally)) { Text("Not now") }
        Spacer(Modifier.height(24.dp))
    }
}

/** A code, as a QR code and as text, with the usual ways to pass it on. */
@Composable
private fun CodeToPass(code: String, label: String, qr: Boolean = true) {
    val context = LocalContext.current
    Column(verticalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
        if (qr) Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { QrCode(code) }
        CodeWell(code, maxLines = 4)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { copyText(context, label, code) }) { Text("Copy") }
            OutlinedButton(onClick = { shareText(context, code) }) { Text("Share") }
        }
    }
}

/**
 * This phone, with no vault, shows a code; a device that has the vault scans
 * or pastes it and sends the vault here. A fresh code replaces an expired one.
 */
@Composable
private fun JoinCodePanel(app: MayiApp, onJoined: () -> Unit, onBack: () -> Unit) {
    var code by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var round by remember { mutableIntStateOf(0) }
    DisposableEffect(round) {
        var invitation: JoinInvitation? = null
        var leaving = false
        Thread {
            try {
                val opened = app.openJoinCode()
                invitation = opened
                code = opened.token()
                val problem = app.joinByCode(opened)
                if (leaving) return@Thread
                if (problem == null) {
                    onJoined()
                } else {
                    if (!problem.contains("expired")) error = "Not joined: $problem"
                    round++
                }
            } catch (e: Exception) {
                error = MayiController.describe(e)
            }
        }.start()
        onDispose {
            leaving = true
            invitation?.cancel()
        }
    }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Show this to your other device", style = MaterialTheme.typography.titleMedium)
        Text(
            "On a phone with your vault: Devices, +, Add a device, Scan its code. On a Mac: Devices, Add a Device, then paste the code.",
            style = MaterialTheme.typography.bodyMedium,
        )
        code?.let { CodeToPass(it, "Mayi code") }
        LinearProgressIndicator(Modifier.fillMaxWidth())
        Text(
            "Waiting for your other device. It asks you to confirm, then sends this phone the vault.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        error?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error) }
        TextButton(onClick = onBack) { Text("Back") }
    }
}

// --- Home -----------------------------------------------------------------------

private class Tab(val title: String, val icon: ImageVector, val selectedIcon: ImageVector)

private val tabs = listOf(
    Tab("Requests", Icons.Outlined.Notifications, Icons.Filled.Notifications),
    Tab("Secrets", Icons.Outlined.Key, Icons.Filled.Key),
    Tab("Devices", Icons.Outlined.Devices, Icons.Filled.Devices),
    Tab("Activity", Icons.Outlined.History, Icons.Filled.History),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun Home(app: MayiApp, scan: ((String) -> Unit) -> Unit, resumes: MutableIntState, openRequests: MutableIntState) {
    val controller = app.controller
    var state by remember { mutableStateOf(controller.state) }
    DisposableEffect(controller) {
        val listener = { s: MayiController.State -> state = s }
        controller.observe(listener)
        controller.refresh()
        onDispose { controller.unobserve(listener) }
    }
    var tab by remember { mutableIntStateOf(0) }
    var adding by remember { mutableStateOf(false) }
    var addingDevice by remember { mutableStateOf(false) }
    val waiting = state.pending.size + state.notices.size
    // A request's notification opens the Requests tab, closing what was open.
    LaunchedEffect(openRequests.intValue) {
        if (openRequests.intValue > 0) {
            tab = 0
            adding = false
            addingDevice = false
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(tabs[tab].title) },
                actions = {
                    if (tab == 2) {
                        IconButton(onClick = { Thread { controller.sync() }.start() }) {
                            Icon(Icons.Outlined.Sync, contentDescription = "Sync now")
                        }
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                tabs.forEachIndexed { index, item ->
                    NavigationBarItem(
                        selected = tab == index,
                        onClick = { tab = index },
                        icon = {
                            BadgedBox(badge = { if (index == 0 && waiting > 0) Badge { Text("$waiting") } }) {
                                Icon(if (tab == index) item.selectedIcon else item.icon, contentDescription = null)
                            }
                        },
                        label = { Text(item.title) },
                    )
                }
            }
        },
        floatingActionButton = {
            if (tab == 1) {
                ExtendedFloatingActionButton(
                    onClick = { adding = true },
                    icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                    text = { Text("Add") },
                )
            } else if (tab == 2) {
                FloatingActionButton(onClick = { addingDevice = true }) {
                    Icon(Icons.Filled.Add, contentDescription = "Add a device, a machine or a recovery key")
                }
            }
        },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (tab) {
                0 -> Requests(controller, state, remember(resumes.intValue) { ReachProblems.of(app) })
                1 -> Secrets(controller, state, adding, scan) { adding = it }
                2 -> Devices(app, controller, state, addingDevice, scan) { addingDevice = it }
                else -> Activity(state.log)
            }
        }
    }
}

// --- Requests ---------------------------------------------------------------------

/** What keeps requests from reaching this phone while Mayi is in the background. */
private data class ReachProblems(val notificationsOff: Boolean, val stoppedInBackground: Boolean, val makerPage: String?) {
    val any get() = notificationsOff || stoppedInBackground

    companion object {
        fun of(app: MayiApp) = ReachProblems(app.notificationsBlocked, !app.backgroundAllowed, app.makerHelpPage)
    }
}

@Composable
private fun Requests(controller: MayiController, state: MayiController.State, problems: ReachProblems) {
    val context = LocalContext.current
    val app = context.applicationContext as MayiApp
    Column {
        if (problems.any) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                modifier = Modifier.fillMaxWidth().padding(16.dp),
            ) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Requests may not reach you", style = MaterialTheme.typography.titleSmall)
                    if (problems.notificationsOff) {
                        Text(
                            "Notifications are off, so a request that arrives while Mayi is in the background cannot tell you.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Button(onClick = {
                            context.startActivity(
                                Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName),
                            )
                        }) { Text("Turn on notifications") }
                    }
                    if (problems.stoppedInBackground) {
                        Text(
                            "Android may stop Mayi in the background to save battery, and then your agents cannot reach this phone.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Button(onClick = { app.askToRunInBackground(context) }) { Text("Allow in the background") }
                        problems.makerPage?.let { page ->
                            TextButton(onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(page))) }) {
                                Text("What else your phone's maker may stop")
                            }
                        }
                    }
                }
            }
        }
        if (state.pending.isEmpty() && state.notices.isEmpty() && state.signIns.isEmpty()) {
            EmptyState(Icons.Outlined.Notifications, "Nothing is waiting for you", "When an agent needs your say, its request appears here.")
            return@Column
        }
        LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            items(state.signIns, key = { "s${it.runId}" }) { needed -> SignInAgainCard(controller, needed) }
            items(state.pending, key = { "p${it.runId}" }) { prompt -> RequestCard(prompt) { controller.answer(prompt.runId, it) } }
            items(state.notices, key = { "n${it.notice.runId}" }) { active ->
                NoticeCard(active, onStop = { controller.stop(active.notice.runId) }, onDismiss = { controller.dismiss(active.notice.runId) })
            }
        }
    }
}

@Composable
private fun Detail(label: String, value: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(60.dp),
        )
        Text(value.ifEmpty { "not given" }, style = MaterialTheme.typography.bodyMedium, maxLines = 3, overflow = TextOverflow.Ellipsis)
    }
}

/**
 * Asks whether a command may use level 3 secrets, or a login may be typed
 * into a website: the question, the command or website, then the details.
 * What the requester says about itself is boxed and labelled as unverified,
 * below the command.
 */
@Composable
private fun RequestCard(prompt: PromptInfo, onChoice: (ApprovalChoice) -> Unit) {
    val scheme = MaterialTheme.colorScheme
    val needed = prompt.secrets.filter { it.needsApproval }
    val site = prompt.request.site
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                AppIcon(44.dp)
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        when {
                            site != null -> "Allow signing in to ${host(site)}?"
                            needed.size == 1 -> "Allow this command to use ${needed[0].name}?"
                            else -> "Allow this command to use ${needed.size} secrets?"
                        },
                        style = MaterialTheme.typography.titleMedium,
                    )
                    RequesterChip(prompt.request)
                }
            }
            CodeWell(site ?: prompt.request.command)
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                for (secret in prompt.secrets) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (site != null) {
                            Icon(Icons.Outlined.Language, contentDescription = null, tint = scheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
                        }
                        Text(
                            secret.name, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace,
                            maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f),
                        )
                        if (!secret.needsApproval) {
                            Text("no approval needed", style = MaterialTheme.typography.labelSmall, color = scheme.outline)
                        }
                        LevelLabel(secret.level.toInt())
                    }
                }
                if (site != null) {
                    Text(
                        "Types ${fieldWords(prompt.request.fields)} into the page.",
                        style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant,
                    )
                }
            }
            Surface(color = scheme.surfaceContainerLow, shape = MaterialTheme.shapes.small, modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        "Stated by the requester, not verified", style = MaterialTheme.typography.labelMedium,
                        color = scheme.onSurfaceVariant,
                    )
                    Detail("Reason", prompt.request.reason)
                    Detail("Agent", prompt.request.agent)
                    Detail("Session", prompt.request.session)
                    Detail("Folder", prompt.request.cwd)
                }
            }
            Text(
                if (site != null) "Once signed in, the agent can act as you on this site."
                else "Once allowed, the command can do anything with the secret, including sending it elsewhere.",
                style = MaterialTheme.typography.bodySmall,
                color = scheme.onSurfaceVariant,
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedButton(onClick = { onChoice(ApprovalChoice.DENY) }) { Text("Deny") }
                Spacer(Modifier.weight(1f))
                Button(onClick = { onChoice(ApprovalChoice.ONCE) }) { Text("Allow once") }
            }
            if (site != null) {
                TextButton(onClick = { onChoice(ApprovalChoice.SESSION_COMMAND) }, contentPadding = PaddingValues(horizontal = 4.dp)) {
                    Text("Allow for the rest of this session")
                }
            } else Column {
                Text("Or allow for the rest of this session", style = MaterialTheme.typography.labelMedium, color = scheme.onSurfaceVariant)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { onChoice(ApprovalChoice.SESSION_COMMAND) }, contentPadding = PaddingValues(horizontal = 4.dp)) {
                        Text("This command")
                    }
                    TextButton(onClick = { onChoice(ApprovalChoice.SESSION_ANY) }, contentPadding = PaddingValues(horizontal = 4.dp)) {
                        Text("Any command")
                    }
                }
            }
        }
    }
}

/** Tells the user secrets were released without asking, with a way to stop. */
@Composable
private fun NoticeCard(active: MayiController.ActiveNotice, onStop: () -> Unit, onDismiss: () -> Unit) {
    val scheme = MaterialTheme.colorScheme
    val names = active.notice.secrets
    val site = active.notice.request.site
    OutlinedCard(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            AppIcon(40.dp)
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    if (site != null) "${names.joinToString()} was typed into ${host(site)}"
                    else names.joinToString() + if (names.size == 1) " was used" else " were used",
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(
                    site ?: active.notice.request.command, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                    color = scheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis,
                )
                if (active.stopped || active.ended) {
                    Text(
                        if (active.stopped) "Stopped, and its session revoked"
                        else if (site != null) "Sign-in done" else "Command finished",
                        style = MaterialTheme.typography.bodySmall,
                        color = scheme.onSurfaceVariant,
                    )
                } else {
                    Spacer(Modifier.height(4.dp))
                    RequesterChip(active.notice.request, compact = true)
                }
                Spacer(Modifier.height(8.dp))
                if (active.ended || active.stopped) {
                    OutlinedButton(onClick = onDismiss) { Text("Dismiss") }
                } else {
                    Button(
                        onClick = onStop,
                        colors = ButtonDefaults.buttonColors(containerColor = scheme.error, contentColor = scheme.onError),
                    ) { Text("Stop") }
                }
            }
        }
    }
}

// --- Secrets ----------------------------------------------------------------------

private fun summary(secret: SecretRecord): String {
    secret.aws?.let { aws ->
        val host = android.net.Uri.parse(aws.startUrl).host ?: aws.startUrl
        val roles = aws.profiles.joinToString { "${it.name} ${it.level}" }
        return "AWS sign-in to $host. Profiles: $roles"
    }
    if (secret.login) {
        val sites = "Signs in to " + secret.sites.joinToString()
        return if ("totp" in secret.fields) "$sites, with a two-factor code" else sites
    }
    val parts = mutableListOf<String>()
    if (secret.fields != listOf("value")) parts.add("Holds " + secret.fields.joinToString())
    parts.add(if (secret.allow.isEmpty()) "Any command may ask for it" else "Expected with " + secret.allow.joinToString())
    return parts.joinToString(". ")
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun Secrets(
    controller: MayiController, state: MayiController.State, adding: Boolean, scan: ((String) -> Unit) -> Unit,
    setAdding: (Boolean) -> Unit,
) {
    var detail by remember { mutableStateOf<SecretRecord?>(null) }
    var editing by remember { mutableStateOf<SecretRecord?>(null) }
    /** Open the edit sheet with the values shown. */
    var showing by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scheme = MaterialTheme.colorScheme
    val app = LocalContext.current.applicationContext as MayiApp
    // The owner confirms with a fingerprint first; a level 4 secret's own
    // unlock asks for it instead.
    val reveal = { secret: SecretRecord, done: (Result<RevealedSecret>) -> Unit ->
        Thread {
            done(
                if (secret.level < 4u && !app.unlock("Show ${secret.name}")) {
                    Result.failure(IllegalStateException("Showing values needs your fingerprint."))
                } else {
                    controller.reveal(secret.name)
                },
            )
        }.start()
    }

    var query by rememberSaveable { mutableStateOf("") }
    var tag by rememberSaveable { mutableStateOf<String?>(null) }
    val tags = remember(state.secrets) { tagsOf(state.secrets) }
    // A tag dropped meanwhile shows everything again.
    val selected = tag?.takeIf { it in tags }
    val shown = remember(state.secrets, query, selected) {
        val words = query.lowercase().split(' ').filter { it.isNotEmpty() }
        state.secrets.filter { secret ->
            val text = (listOf(secret.name) + secret.tags + secret.sites + secret.fields).joinToString(" ").lowercase()
            (selected == null || secret.tags.any { it.equals(selected, ignoreCase = true) }) && words.all { it in text }
        }
    }
    val focus = LocalFocusManager.current

    if (state.secrets.isEmpty()) {
        EmptyState(Icons.Outlined.Key, "No secrets yet", "Add an API key, a token or a website login. An agent then uses it by name and never sees the value.")
    } else {
        LazyColumn {
            item(key = "search") {
                OutlinedTextField(
                    query, { query = it }, Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
                    placeholder = { Text("Search secrets") }, singleLine = true, shape = CircleShape,
                    leadingIcon = { Icon(Icons.Outlined.Search, contentDescription = null) },
                    trailingIcon = if (query.isEmpty()) null else ({
                        IconButton(onClick = { query = "" }) { Icon(Icons.Outlined.Close, contentDescription = "Clear search") }
                    }),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = { focus.clearFocus() }),
                )
            }
            if (tags.isNotEmpty()) {
                item(key = "tags") {
                    Row(
                        Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 16.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        FilterChip(selected = selected == null, onClick = { tag = null }, label = { Text("All") })
                        for (name in tags) {
                            FilterChip(
                                selected = selected == name, onClick = { tag = if (selected == name) null else name },
                                label = { Text(name) },
                                leadingIcon = { Icon(Icons.Outlined.Sell, contentDescription = null, Modifier.size(FilterChipDefaults.IconSize)) },
                            )
                        }
                    }
                }
            }
            error?.let { message ->
                item { Text(message, style = MaterialTheme.typography.bodyMedium, color = scheme.error, modifier = Modifier.padding(horizontal = 16.dp)) }
            }
            if (shown.isEmpty()) {
                item {
                    Text(
                        if (query.isEmpty()) "Nothing is tagged $selected." else "No secret matches “${query.trim()}”" + (selected?.let { " among those tagged $it." } ?: "."),
                        style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 24.dp),
                    )
                }
            }
            items(shown, key = { it.name }) { secret ->
                val flagged = secret.rotate.isNotEmpty()
                ListItem(
                    leadingContent = {
                        if (secret.aws != null) {
                            AwsLogo()
                        } else {
                            Icon(
                                if (secret.login) Icons.Outlined.Language else Icons.Outlined.Key,
                                contentDescription = if (secret.login) "Website login" else "Secret",
                            )
                        }
                    },
                    headlineContent = {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            if (flagged) {
                                Icon(Icons.Filled.Warning, contentDescription = "Replace this value", tint = oneCopyColor, modifier = Modifier.size(18.dp))
                            }
                            Text(
                                secret.name, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f, fill = false),
                            )
                            if (secret.copies < 2u) OneCopyDot()
                        }
                    },
                    supportingContent = {
                        Text(
                            if (flagged) "May be known to " + secret.rotate.joinToString { it.who } + ". Tap for what to do."
                            else summary(secret),
                            maxLines = 1, overflow = TextOverflow.Ellipsis,
                        )
                    },
                    trailingContent = {
                        val aws = secret.aws
                        if (aws != null) Text(if (aws.profiles.size == 1) "1 profile" else "${aws.profiles.size} profiles")
                        else LevelLabel(secret.level.toInt())
                    },
                    modifier = Modifier.clickable { detail = secret },
                )
            }
            // Room for the Add button to float without covering the last row.
            item { Spacer(Modifier.height(88.dp)) }
        }
    }

    if (adding) {
        ModalBottomSheet(
            onDismissRequest = { setAdding(false) },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        ) {
            AddSecret(
                scan = scan, existing = null, onCancel = { setAdding(false) }, tagsInUse = tags, tag = selected,
                usableBy = controller::usableBy, controller = controller,
            ) { draft, done ->
                saveInBackground(controller, draft) { problem ->
                    if (problem == null) setAdding(false)
                    done(problem)
                }
            }
        }
    }
    editing?.let { secret ->
        ModalBottomSheet(
            onDismissRequest = { editing = null },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        ) {
            AddSecret(
                scan = scan, existing = secret, onCancel = { editing = null },
                reveal = { done -> reveal(secret, done) }, revealOnOpen = showing,
                loadsAtOnce = app.unlocked && secret.level < 4u, tagsInUse = tags, usableBy = controller::usableBy,
                onDismissRotation = { controller.dismissRotation(secret.name) },
            ) { draft, done ->
                saveInBackground(controller, draft) { problem ->
                    if (problem == null) editing = null
                    done(problem)
                }
            }
        }
    }
    detail?.let { secret ->
        ModalBottomSheet(onDismissRequest = { detail = null }, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
            Column(
                Modifier.padding(horizontal = 24.dp).padding(bottom = 28.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (secret.aws == null) {
                    Text(secret.name, style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace)
                    LevelLabel(secret.level.toInt(), color = scheme.onSurface)
                    Text(
                        (if (secret.login) loginLevelDetails else levelDetails)[secret.level.toInt() - 1],
                        style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant,
                    )
                } else {
                    AwsSignInEditor(controller, secret) { detail = null }
                }
                if (secret.aws == null) Text(summary(secret) + ".", style = MaterialTheme.typography.bodyMedium)
                if (secret.tags.isNotEmpty()) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Outlined.Sell, contentDescription = null, tint = scheme.onSurfaceVariant, modifier = Modifier.size(18.dp))
                        Text("Tagged " + secret.tags.joinToString(", "), style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant)
                    }
                }
                if (secret.copies < 2u) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OneCopyDot()
                        Text(
                            "Only on this phone. It reaches your other devices when they next sync; add a device to keep a second copy.",
                            style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant,
                        )
                    }
                }
                if (secret.rotate.isNotEmpty()) {
                    RotationCard(secret.rotate) {
                        error = controller.dismissRotation(secret.name)
                        detail = controller.state.secrets.find { it.name == secret.name }
                    }
                }
                Spacer(Modifier.height(4.dp))
                if (secret.aws == null) Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = {
                        showing = true
                        editing = secret
                        detail = null
                    }) { Text("Show values") }
                    OutlinedButton(onClick = {
                        showing = false
                        editing = secret
                        detail = null
                    }) { Text("Edit") }
                }
                TextButton(onClick = {
                    deleting = secret.name
                    detail = null
                }) { Text(if (secret.login) "Delete login" else "Delete secret", color = scheme.error) }
            }
        }
    }
    deleting?.let { name ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text("Delete $name?") },
            text = { Text("Agents will no longer be able to use it.") },
            confirmButton = {
                TextButton(onClick = {
                    error = controller.deleteSecret(name)
                    Thread { controller.sync() }.start()
                    deleting = null
                }) { Text("Delete", color = scheme.error) }
            },
            dismissButton = { TextButton(onClick = { deleting = null }) { Text("Cancel") } },
        )
    }
}

/** What the add or edit sheet produces. [values] empty means keep the stored values. */
private class NewSecret(
    val name: String, val level: UByte, val values: Map<String, String>, val allow: List<String>,
    val maxGrantSecs: ULong, val login: Boolean, val sites: List<String>, val tags: List<String>,
)

/** The tags in use, sorted, each once whatever its case. */
private fun tagsOf(secrets: List<SecretRecord>) =
    secrets.flatMap { it.tags }.distinctBy { it.lowercase() }.sortedWith(String.CASE_INSENSITIVE_ORDER)

/** "work, ci" as typed into the tags field. */
private fun tagList(text: String) = text.split(',').map { it.trim() }.filter { it.isNotEmpty() }

private fun lines(text: String) = text.lines().map { it.trim() }.filter { it.isNotEmpty() }

/**
 * [save] off the main thread, answering on it: saving may ask for a
 * fingerprint (lowering a level, adding an expected command), and that
 * prompt needs the main thread free.
 */
private fun saveInBackground(controller: MayiController, draft: NewSecret, done: (String?) -> Unit) {
    val main = Handler(Looper.getMainLooper())
    Thread {
        val problem = save(controller, draft)
        main.post { done(problem) }
    }.start()
}

/** Stores a draft: new values, or only the rules when no value was entered. Blocks. */
private fun save(controller: MayiController, draft: NewSecret): String? {
    val problem = if (draft.values.isEmpty()) {
        controller.updateRules(draft.name, draft.allow, draft.maxGrantSecs, draft.sites, draft.tags)
    } else {
        controller.saveSecret(draft.name, draft.level, draft.values, draft.allow, draft.maxGrantSecs, draft.login, draft.sites, draft.tags)
    }
    if (problem == null) Thread { controller.sync() }.start()
    return problem
}

private val grantChoices = listOf(0uL to "Every time", 300uL to "5 min", 900uL to "15 min", 3600uL to "1 hour")

/**
 * Adds a secret or a login, or edits [existing]. When editing, leaving every
 * value empty keeps what is stored and changes only the rules. Returns an
 * error message from [onSave] to keep the sheet open and show it.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddSecret(
    scan: ((String) -> Unit) -> Unit, existing: SecretRecord?, onCancel: () -> Unit,
    /** Decrypts the stored values once the owner confirms; calls back on any thread. */
    reveal: (((Result<RevealedSecret>) -> Unit) -> Unit)? = null,
    /** Show the values as soon as the sheet opens. */
    revealOnOpen: Boolean = false,
    /** Load the values when the sheet opens, hidden behind their eyes: when that asks nothing. */
    loadsAtOnce: Boolean = false,
    /** The tags in use, offered as suggestions. */
    tagsInUse: List<String> = emptyList(),
    /** The tag a new secret starts with. */
    tag: String? = null,
    /** Who could use a secret with this name and these tags, shown as they change. */
    usableBy: ((String, List<String>) -> List<String>)? = null,
    /** Drops the note that this secret should be replaced; returns an error. */
    onDismissRotation: (() -> String?)? = null,
    /** When adding: offers an AWS sign-in as a third type. */
    controller: MayiController? = null,
    /** Saves [NewSecret] and calls back on the main thread with an error, or null once saved. */
    onSave: (NewSecret, (String?) -> Unit) -> Unit,
) {
    val editing = existing != null
    var login by remember { mutableStateOf(existing?.login ?: false) }
    var aws by remember { mutableStateOf(false) }
    var saving by remember { mutableStateOf(false) }
    var name by remember { mutableStateOf(existing?.name ?: "") }
    var value by remember { mutableStateOf("") }
    var allow by remember { mutableStateOf(existing?.allow?.joinToString("\n") ?: "") }
    var sites by remember { mutableStateOf(existing?.sites?.joinToString("\n") ?: "") }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var twoFactor by remember { mutableStateOf("") }
    var level by remember { mutableIntStateOf(existing?.level?.toInt() ?: 3) }
    var maxGrant by remember { mutableStateOf(existing?.maxGrantSecs ?: 900uL) }
    var tagsText by remember { mutableStateOf(existing?.tags?.joinToString(", ") ?: tag ?: "") }
    var rotationDismissed by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scheme = MaterialTheme.colorScheme
    val mono = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace)
    val context = LocalContext.current
    val severalFields = existing != null && !existing.login && existing.fields != listOf("value")
    /** The stored values, once shown: saving them unchanged changes only the rules. */
    var shown by remember { mutableStateOf<Map<String, String>?>(null) }
    val fieldValues = remember { mutableStateMapOf<String, String>() }
    /** Drop the stored two-factor key on saving. */
    var removeTwoFactor by remember { mutableStateOf(false) }
    var revealing by remember { mutableStateOf(false) }
    fun showValues() {
        val decrypt = reveal ?: return
        revealing = true
        error = null
        decrypt { result ->
            revealing = false
            result.onSuccess { revealed ->
                val values = revealed.fields.associate { it.name to it.value }
                when {
                    // The two-factor key stays out of its field: the sheet
                    // shows the code it gives instead.
                    existing?.login == true -> {
                        username = values["username"] ?: ""
                        password = values["password"] ?: ""
                    }
                    severalFields -> {
                        fieldValues.clear()
                        fieldValues.putAll(values)
                    }
                    else -> value = values["value"] ?: ""
                }
                shown = values
            }.onFailure { error = MayiController.describe(it) }
        }
    }
    LaunchedEffect(Unit) { if (revealOnOpen || loadsAtOnce) showValues() }
    val keep = if (editing && shown == null) "unchanged" else null
    val storedKey = shown?.get("totp")?.takeIf { !removeTwoFactor }
    /** The two-factor key saving keeps: a new one typed, else the stored one. */
    val twoFactorKey = twoFactor.trim().ifEmpty { null } ?: storedKey
    val copy = @Composable { text: String ->
        IconButton(onClick = { copySecret(context, text) }, enabled = text.isNotEmpty()) {
            Icon(Icons.Outlined.ContentCopy, contentDescription = "Copy")
        }
    }
    /**
     * A value field: hidden while typing, with an eye to check what was typed;
     * readable, with a copy button, once the stored values are shown, unless
     * [private] (a two-factor key, which is never shown).
     */
    @Composable
    fun SecretField(
        text: String, set: (String) -> Unit, label: String, hint: String? = keep, private: Boolean = false,
        readOnly: Boolean = false, trailing: (@Composable () -> Unit)? = null,
    ) {
        key(label) {
            var peek by remember { mutableStateOf(revealOnOpen && !private) }
            // The eye's first press on a stored secret loads its values.
            val loadFirst = editing && shown == null && reveal != null && !private
            OutlinedTextField(
                text, set, Modifier.fillMaxWidth(), label = { Text(label) }, singleLine = true, readOnly = readOnly,
                placeholder = hint?.let { { Text(it) } },
                visualTransformation = if (peek) VisualTransformation.None else PasswordVisualTransformation(),
                textStyle = if (peek) mono else MaterialTheme.typography.bodyLarge,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    Row {
                        if (shown != null && !private) copy(text)
                        trailing?.invoke()
                        IconButton(onClick = {
                            if (!peek && loadFirst) showValues()
                            peek = !peek
                        }) {
                            Icon(
                                if (peek) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                                contentDescription = when {
                                    peek -> "Hide"
                                    loadFirst -> "Show the current value"
                                    else -> "Show"
                                },
                            )
                        }
                    }
                },
            )
        }
    }
    val shownHint = "Edit what you need and save. Copied values are cleared from the clipboard after a minute."
    Column(
        Modifier.padding(horizontal = 24.dp).padding(bottom = 24.dp).imePadding().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(
            when {
                existing != null -> "Edit ${existing.name}"
                aws -> "New AWS sign-in"
                login -> "New login"
                else -> "New secret"
            },
            style = MaterialTheme.typography.titleLarge,
        )
        if (!editing) {
            val kinds = listOfNotNull("Secret", "Login", controller?.let { "AWS" })
            val chosen = if (aws) 2 else if (login) 1 else 0
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                kinds.forEachIndexed { index, label ->
                    SegmentedButton(
                        selected = chosen == index,
                        onClick = { aws = index == 2; login = index == 1 },
                        shape = SegmentedButtonDefaults.itemShape(index, kinds.size),
                    ) { Text(label, maxLines = 1) }
                }
            }
            if (aws && controller != null) {
                AwsSignInForm(controller, tag, onCancel = onCancel, onDone = onCancel)
                return@Column
            }
            OutlinedTextField(
                name, { name = it }, Modifier.fillMaxWidth(), label = { Text("Name") },
                placeholder = { Text(if (login) "github" else "GITHUB_TOKEN") }, textStyle = mono, singleLine = true,
            )
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            OutlinedTextField(
                tagsText, { tagsText = it }, Modifier.fillMaxWidth(), label = { Text("Tags (optional)") }, singleLine = true,
                placeholder = { Text("work, ci") },
                leadingIcon = { Icon(Icons.Outlined.Sell, contentDescription = null) },
                // A tag can let a machine use the secret, so say which ones would.
                supportingText = usableBy?.let { find ->
                    {
                        val who = remember(name, tagsText) { find(name.trim(), tagList(tagsText)) }
                        Text(if (who.isEmpty()) "No machine may use it" else "Usable by " + who.joinToString(", "))
                    }
                },
            )
            // The tags in use that fit the one being typed, one tap away.
            val chosen = tagList(tagsText)
            val typing = tagsText.substringAfterLast(',').trim()
            val offered = tagsInUse.filter { t -> chosen.none { it.equals(t, ignoreCase = true) } && t.startsWith(typing, ignoreCase = true) }
            if (offered.isNotEmpty()) {
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    for (name in offered) {
                        SuggestionChip(
                            onClick = { tagsText = (tagList(tagsText.substringBeforeLast(',', "")) + name).joinToString(", ") + ", " },
                            label = { Text(name) },
                        )
                    }
                }
            }
        }
        if (login) {
            OutlinedTextField(
                sites, { sites = it }, Modifier.fillMaxWidth(), label = { Text("Websites, one per line") },
                placeholder = { Text("github.com") }, textStyle = mono, minLines = 1,
                supportingText = { Text("As the address bar shows them. *.example.com covers its subdomains. Typed into these sites only, over https.") },
            )
            // A stored login changes only once its values are loaded, so that
            // what is not retyped is kept.
            val locked = editing && shown == null
            OutlinedTextField(
                username, { username = it }, Modifier.fillMaxWidth(), label = { Text("Username (optional)") }, singleLine = true,
                readOnly = locked, placeholder = if (locked) ({ Text("unchanged") }) else null,
                trailingIcon = if (shown != null) ({ copy(username) }) else null,
            )
            SecretField(password, { password = it }, "Password", hint = if (locked) "unchanged" else null, readOnly = locked)
            twoFactorKey?.let { TwoFactorCodeRow(it, copy) }
            if (!locked) {
                SecretField(
                    twoFactor, { twoFactor = it }, if (storedKey != null) "New two-factor key" else "Two-factor key (optional)",
                    hint = if (storedKey != null) "unchanged" else null, private = true,
                ) {
                    IconButton(onClick = { scan { twoFactor = it } }) {
                        Icon(Icons.Outlined.QrCodeScanner, contentDescription = "Scan the site’s QR code")
                    }
                }
                if (storedKey != null && twoFactor.isEmpty()) {
                    TextButton(onClick = { removeTwoFactor = true }) { Text("Remove two-factor key", color = scheme.error) }
                }
            }
            Text(
                when {
                    shown != null -> "The code is what the site asks for now; the key behind it is never shown. To replace the key, scan its QR code or paste a new one. Copied values are cleared from the clipboard after a minute."
                    revealing -> "Waiting for you to confirm…"
                    editing -> "Tap the eye to see the current values and change them. Changing the level needs them too."
                    else -> "The two-factor key is what a site shows when you turn on an authenticator app: scan its QR code, or paste the key. It stays on your devices; a page only ever gets the current code."
                },
                style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant,
            )
        } else if (severalFields) {
            for (field in existing?.fields.orEmpty()) {
                SecretField(fieldValues[field] ?: "", { fieldValues[field] = it }, field)
            }
            Text(
                if (shown != null) shownHint
                else "Tap an eye to see the current values, or type new ones for every field; all empty keeps them.",
                style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant,
            )
        } else {
            SecretField(value, { value = it }, "Value")
            if (editing) {
                Text(
                    if (shown != null) shownHint
                    else "Tap the eye to see the current value, or type a new one; empty keeps it. Changing the level needs the value again.",
                    style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant,
                )
            }
        }
        Column {
            Text("Level", style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(bottom = 4.dp))
            for (step in 1..4) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .selectable(
                            selected = level == step, role = Role.RadioButton, enabled = !severalFields || shown != null,
                            onClick = { level = step },
                        )
                        .padding(vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    RadioButton(selected = level == step, onClick = null, enabled = !severalFields || shown != null)
                    Icon(levelIcon(step), contentDescription = null, tint = scheme.onSurfaceVariant, modifier = Modifier.size(20.dp))
                    Column {
                        Text(levelNames[step - 1], style = MaterialTheme.typography.bodyLarge)
                        Text(
                            (if (login) loginLevelDetails else levelDetails)[step - 1],
                            style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("An approval lasts at most", style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for ((secs, label) in grantChoices) {
                    FilterChip(selected = maxGrant == secs, onClick = { maxGrant = secs }, label = { Text(label) })
                }
            }
        }
        if (!login) {
            OutlinedTextField(
                allow, { allow = it }, Modifier.fillMaxWidth(), label = { Text("Expected commands, one per line") },
                textStyle = mono, minLines = 2,
                supportingText = { Text("An expected command skips the prompt at level 3. Any other command is asked about.") },
            )
        }
        if (existing != null && existing.rotate.isNotEmpty() && !rotationDismissed) {
            RotationCard(existing.rotate) {
                val problem = onDismissRotation?.invoke()
                if (problem == null) rotationDismissed = true else error = problem
            }
        }
        error?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = scheme.error) }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Spacer(Modifier.weight(1f))
            TextButton(onClick = onCancel) { Text("Cancel") }
            Button(
                onClick = {
                    val entered: Map<String, String> = when {
                        login && editing && username.isEmpty() && password.isEmpty() && twoFactor.isEmpty() -> emptyMap()
                        login -> buildMap {
                            put("password", password)
                            if (username.isNotBlank()) put("username", username.trim())
                            twoFactorKey?.let { put("totp", it) }
                        }
                        severalFields && fieldValues.values.all { it.isEmpty() } -> emptyMap()
                        severalFields -> existing?.fields.orEmpty().associateWith { fieldValues[it] ?: "" }
                        editing && value.isEmpty() -> emptyMap()
                        else -> mapOf("value" to value)
                    }
                    // Shown values saved as they were: only the rules change.
                    val values = if (entered == shown && level == existing?.level?.toInt()) emptyMap() else entered
                    error = when {
                        name.isBlank() -> "Give it a name."
                        login && lines(sites).isEmpty() -> "Add the website this login is for."
                        login && values.isNotEmpty() && password.isEmpty() -> "Enter the password."
                        severalFields && values.values.any { it.isEmpty() } -> "Enter a value for every field."
                        !editing && values.isEmpty() -> "Enter the value."
                        editing && values.isEmpty() && level != existing?.level?.toInt() ->
                            if (login) "Changing the level re-encrypts it, so show its values first."
                            else "Changing the level re-encrypts it, so show or enter its value again."
                        else -> {
                            saving = true
                            onSave(
                                NewSecret(
                                    name.trim(), level.toUByte(), values, if (login) emptyList() else lines(allow), maxGrant, login,
                                    if (login) lines(sites) else emptyList(), tagList(tagsText),
                                ),
                            ) { problem ->
                                saving = false
                                error = problem
                            }
                            null
                        }
                    }
                },
                enabled = !saving,
            ) { Text(if (editing) "Save" else if (login) "Add login" else "Add secret") }
        }
    }
}

/** "123456" as "123 456", as authenticator apps show it. */
private fun grouped(code: String) = if (code.length > 4) code.substring(0, code.length / 2) + " " + code.substring(code.length / 2) else code

/** The code a two-factor key gives now, kept current, with a copy button. */
@Composable
private fun TwoFactorCodeRow(key: String, copy: @Composable (String) -> Unit) {
    var tick by remember { mutableLongStateOf(0L) }
    LaunchedEffect(key) {
        while (true) {
            kotlinx.coroutines.delay(1000)
            tick++
        }
    }
    val current = remember(key, tick) { runCatching { twoFactorCode(key) }.getOrNull() }
    if (current == null) {
        Text("Not a two-factor key", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        return
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text("Two-factor code", style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Text(grouped(current.code), style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace)
        Text(
            "  ${current.validSecs} s", style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        copy(current.code)
    }
}

// --- Devices ----------------------------------------------------------------------

/**
 * Adding a device, either way round: the new device shows a code (a Mac in
 * its setup window) and this phone scans it; or this phone shows an
 * invitation and the new device scans or pastes it.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddDevice(
    app: MayiApp, controller: MayiController, state: MayiController.State, scan: ((String) -> Unit) -> Unit,
    onClose: () -> Unit,
) {
    var showing by remember { mutableStateOf(false) }
    var code by remember { mutableStateOf("") }
    var invitation by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var added by remember { mutableStateOf<String?>(null) }
    val scheme = MaterialTheme.colorScheme
    val add = { text: String ->
        busy = true
        error = null
        Thread {
            val result = controller.addDevice(text)
            busy = false
            result.onSuccess { added = it }.onFailure { error = it.message }
        }.start()
    }
    val invite = {
        showing = true
        error = null
        Thread {
            if (!app.unlock("Add a device that will hold all your secrets")) {
                error = "Adding a device needs your fingerprint."
            } else {
                controller.startEnrolment(600u).onSuccess { invitation = it }.onFailure { error = it.message }
            }
        }.start()
    }
    val close = {
        controller.cancelInvitation()
        onClose()
    }
    ModalBottomSheet(onDismissRequest = { if (!busy) close() }, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(
            Modifier.padding(horizontal = 24.dp).padding(bottom = 28.dp).imePadding().verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text("Add a device", style = MaterialTheme.typography.titleLarge)
            val name = added ?: state.lastDeviceAdded.takeIf { invitation != null }
            if (name != null) {
                Text("$name was added. It now holds a copy of every secret and can answer requests.", style = MaterialTheme.typography.bodyLarge)
                Row {
                    Spacer(Modifier.weight(1f))
                    Button(onClick = close) { Text("Done") }
                }
                return@Column
            }
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                SegmentedButton(selected = !showing, onClick = { showing = false }, shape = SegmentedButtonDefaults.itemShape(0, 2)) {
                    Text("Scan its code")
                }
                SegmentedButton(
                    selected = showing, onClick = { if (invitation == null) invite() else showing = true },
                    shape = SegmentedButtonDefaults.itemShape(1, 2),
                ) {
                    Text("Show an invitation")
                }
            }
            if (!showing) {
                Text(
                    "Start setting up Mayi on the new device: a Mac shows a code under Join Your Vault, a phone under Show a code. Scan it here.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Button(onClick = { scan { add(it) } }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Outlined.QrCodeScanner, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Scan code")
                }
                OutlinedTextField(
                    code, { code = it }, Modifier.fillMaxWidth(), label = { Text("Or enter the code as text") },
                    placeholder = { Text("mayij1.…") }, textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                    enabled = !busy, minLines = 2,
                )
                if (busy) {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    Text(
                        "Adding. If you have level 4 secrets, confirm with your fingerprint.",
                        style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant,
                    )
                }
            } else {
                Text(
                    "On a new phone, choose Scan code from another device. On a new Mac, paste it under Use an Invitation. It works once, within 10 minutes.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                invitation?.let {
                    CodeToPass(it, "Mayi invitation")
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                }
            }
            error?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = scheme.error) }
            Text(
                "The new device receives the whole vault, so add only a device you own.",
                style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Spacer(Modifier.weight(1f))
                TextButton(onClick = close, enabled = !busy) { Text("Cancel") }
                if (!showing) Button(onClick = { add(code) }, enabled = !busy && code.isNotBlank()) { Text("Add") }
            }
        }
    }
}

/** An ACL being edited: every secret, or chosen tags and secrets. */
private data class AclDraft(val all: Boolean = false, val tags: Set<String> = emptySet(), val secrets: Set<String> = emptySet()) {
    val record get() = AclRecord(all, tags.sortedWith(String.CASE_INSENSITIVE_ORDER), secrets.sorted())

    /** Grants nothing, so there is nothing to save yet. */
    val isEmpty get() = !all && tags.isEmpty() && secrets.isEmpty()

    fun allows(secret: SecretRecord) =
        all || secret.name in secrets || secret.tags.any { tag -> tags.any { it.equals(tag, ignoreCase = true) } }

    companion object {
        fun of(acl: AclRecord?) = AclDraft(acl?.all ?: false, acl?.tags?.toSet() ?: emptySet(), acl?.secrets?.toSet() ?: emptySet())
    }
}

/** "all secrets", "#ci, #work, PROD_DB", or "nothing", for a machine's row. */
private fun aclSummary(acl: AclRecord) =
    if (acl.all) "all secrets" else (acl.tags.map { "#$it" } + acl.secrets).joinToString(", ").ifEmpty { "nothing" }

/**
 * Chooses which secrets a machine may use: every secret, whole tags, or
 * single secrets. Nothing is ticked to start with for a new machine, and it
 * cannot be confirmed until something is.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AclSheet(
    title: String, message: String, confirm: String, acl: AclRecord?, secrets: List<SecretRecord>,
    onConfirm: (AclRecord) -> String?, onCancel: () -> Unit,
) {
    var draft by remember { mutableStateOf(AclDraft.of(acl)) }
    var query by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val tags = remember(secrets) { tagsOf(secrets) }
    val scheme = MaterialTheme.colorScheme
    // Rows on the sheet's own background.
    val clear = ListItemDefaults.colors(containerColor = Color.Transparent)
    val shown = remember(secrets, query) {
        val words = query.lowercase().split(' ').filter { it.isNotEmpty() }
        secrets.filter { secret -> (listOf(secret.name) + secret.tags).joinToString(" ").lowercase().let { text -> words.all { it in text } } }
    }
    val heading = @Composable { text: String ->
        Text(
            text, style = MaterialTheme.typography.titleSmall, color = scheme.primary,
            modifier = Modifier.padding(start = 24.dp, end = 24.dp, top = 16.dp, bottom = 4.dp),
        )
    }
    ModalBottomSheet(onDismissRequest = onCancel, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        LazyColumn(Modifier.weight(1f, fill = false)) {
            item {
                Column(Modifier.padding(horizontal = 24.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(title, style = MaterialTheme.typography.titleLarge)
                    Text(message, style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant)
                }
            }
            item {
                ListItem(
                    colors = clear,
                    headlineContent = { Text("All secrets") },
                    supportingContent = { Text("Including ones added later") },
                    trailingContent = { Switch(checked = draft.all, onCheckedChange = null) },
                    modifier = Modifier.padding(horizontal = 8.dp)
                        .toggleable(draft.all, role = Role.Switch) { draft = draft.copy(all = it) },
                )
            }
            if (!draft.all) {
                if (tags.isNotEmpty()) {
                    item { heading("Tags") }
                    items(tags, key = { "tag:$it" }) { tag ->
                        val on = tag in draft.tags
                        ListItem(
                            colors = clear,
                            leadingContent = { Checkbox(checked = on, onCheckedChange = null) },
                            headlineContent = { Text(tag) },
                            trailingContent = { Text("${secrets.count { s -> s.tags.any { it.equals(tag, ignoreCase = true) } }}") },
                            modifier = Modifier.padding(horizontal = 8.dp).toggleable(on, role = Role.Checkbox) {
                                draft = draft.copy(tags = if (it) draft.tags + tag else draft.tags - tag)
                            },
                        )
                    }
                    item {
                        Text(
                            "A tag covers the secrets that carry it now and any tagged later.",
                            style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 24.dp),
                        )
                    }
                }
                item { heading("Secrets") }
                if (secrets.isEmpty()) {
                    item {
                        Text(
                            "No secrets yet. Choose All secrets, or add some first.",
                            style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 24.dp),
                        )
                    }
                } else if (secrets.size > 6) {
                    item {
                        OutlinedTextField(
                            query, { query = it }, Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
                            placeholder = { Text("Search secrets") }, singleLine = true, shape = CircleShape,
                            leadingIcon = { Icon(Icons.Outlined.Search, contentDescription = null) },
                        )
                    }
                }
                items(shown, key = { "secret:${it.name}" }) { secret ->
                    val on = secret.name in draft.secrets
                    ListItem(
                        colors = clear,
                        leadingContent = { Checkbox(checked = on, onCheckedChange = null) },
                        headlineContent = { Text(secret.name, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        // Granted through a tag already: no need to tick it.
                        supportingContent = if (!on && draft.allows(secret)) ({ Text("Through a tag") }) else null,
                        modifier = Modifier.padding(horizontal = 8.dp).toggleable(on, role = Role.Checkbox) {
                            draft = draft.copy(secrets = if (it) draft.secrets + secret.name else draft.secrets - secret.name)
                        },
                    )
                }
            }
        }
        Column(Modifier.padding(horizontal = 24.dp).padding(top = 12.dp, bottom = 28.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            error?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = scheme.error) }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (draft.all) "Can use every secret" else "Can use ${secrets.count(draft::allows)} of ${secrets.size}",
                    style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant, modifier = Modifier.weight(1f),
                )
                TextButton(onClick = onCancel) { Text("Cancel") }
                Button(onClick = { error = onConfirm(draft.record) }, enabled = !draft.isEmpty) { Text(confirm) }
            }
        }
    }
}

/**
 * Pairs a machine: first what it may use, then an invitation, a command to
 * run there.
 */
@Composable
private fun PairMachine(app: MayiApp, controller: MayiController, state: MayiController.State, onClose: () -> Unit) {
    var acl by remember { mutableStateOf<AclRecord?>(null) }
    val chosen = acl
    if (chosen == null) {
        AclSheet(
            title = "Pair a machine",
            message = "Choose what the new machine may use. It is refused anything else, without asking you.",
            confirm = "Next", acl = null, secrets = state.secrets,
            onConfirm = {
                acl = it
                null
            },
            onCancel = onClose,
        )
    } else {
        PairingInvitation(app, controller, state, chosen, onClose)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PairingInvitation(
    app: MayiApp, controller: MayiController, state: MayiController.State, acl: AclRecord, onClose: () -> Unit,
) {
    var token by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    DisposableEffect(Unit) {
        Thread {
            if (!app.unlock("Allow another machine to request secrets")) {
                error = "Pairing needs your fingerprint."
            } else {
                controller.startPairing(600u, acl).onSuccess { token = it }.onFailure { error = it.message }
            }
        }.start()
        onDispose { controller.cancelInvitation() }
    }
    ModalBottomSheet(onDismissRequest = onClose, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(
            Modifier.padding(horizontal = 24.dp).padding(bottom = 28.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text("Pair a machine", style = MaterialTheme.typography.titleLarge)
            val paired = state.lastPaired.takeIf { token != null }
            if (paired != null) {
                Text("Paired with $paired. It can now ask this vault for secrets; it stores none.", style = MaterialTheme.typography.bodyLarge)
            } else {
                Text(
                    "Run this on the machine within 10 minutes. It must reach this phone on the same network or over Tailscale.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                token?.let {
                    CodeToPass("mayi pair $it", "Mayi pairing", qr = false)
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                }
                Text(
                    "It may use: " + aclSummary(acl) + ".",
                    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            error?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error) }
            Row {
                Spacer(Modifier.weight(1f))
                Button(onClick = onClose) { Text(if (paired != null) "Done" else "Close") }
            }
        }
    }
}

/** The recovery key, shown once. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RecoveryKey(key: String, onClose: () -> Unit) {
    ModalBottomSheet(onDismissRequest = {}, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(
            Modifier.padding(horizontal = 24.dp).padding(bottom = 28.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text("Recovery key", style = MaterialTheme.typography.titleLarge)
            Text(
                "Write it down or print it, and keep it somewhere offline. It is not stored, and it is not shown again.",
                style = MaterialTheme.typography.bodyMedium,
            )
            CodeToPass(key, "Mayi recovery key", qr = false)
            Text(
                "With this key and a copy of the vault file, anyone can read every secret. It restores a Mac whose keys were lost. Making a new key replaces this one.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row {
                Spacer(Modifier.weight(1f))
                Button(onClick = onClose) { Text("I have saved it") }
            }
        }
    }
}

private fun rotationAdvice(names: List<String>, what: String) =
    if (names.isEmpty()) "Nothing to rotate: $what no secret." else "Rotate these secrets, which $what: ${names.joinToString()}."

@Composable
private fun Devices(
    app: MayiApp, controller: MayiController, state: MayiController.State, adding: Boolean,
    scan: ((String) -> Unit) -> Unit, setAdding: (Boolean) -> Unit,
) {
    val scheme = MaterialTheme.colorScheme
    val activity = LocalContext.current as? Activity
    var pairing by remember { mutableStateOf(false) }
    var removing by remember { mutableStateOf<DeviceInfo?>(null) }
    var advice by remember { mutableStateOf<String?>(null) }
    var recoveryKey by remember { mutableStateOf<String?>(null) }
    var confirmJoin by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    /** The machine, or the device whose agents, whose ACL is being edited. */
    var editingAcl by remember { mutableStateOf<Any?>(null) }
    // Agents on a vault device have one ACL, kept with that device; the
    // machine record it paired through is that same list, so it is not shown.
    val agentDevices = state.devices.filter { it.agentsAcl != null && !it.removed }
    val paired = state.machines.filter { it.runsDevice == null }.sortedBy { it.revoked }
    var addingDevice by remember { mutableStateOf(false) }
    val createRecoveryKey = {
        Thread {
            if (!app.unlock("Create a key that can open your vault without this phone")) {
                error = "Creating a recovery key needs your fingerprint."
            } else {
                controller.createRecoveryKey()
                    .onSuccess {
                        recoveryKey = it
                        error = null
                    }
                    .onFailure { error = it.message }
            }
        }.start()
    }

    if (adding) {
        AddChoice(
            onPair = {
                setAdding(false)
                pairing = true
            },
            onDevice = {
                setAdding(false)
                addingDevice = true
            },
            onRecovery = {
                setAdding(false)
                createRecoveryKey()
            },
            onDismiss = { setAdding(false) },
        )
    }
    if (addingDevice) AddDevice(app, controller, state, scan) { addingDevice = false }
    if (pairing) PairMachine(app, controller, state) { pairing = false }
    recoveryKey?.let { RecoveryKey(it) { recoveryKey = null } }
    when (val target = editingAcl) {
        is MachineRecord -> AclSheet(
            title = "ACL for ${target.name}", message = "What this machine may use. It is refused anything else, without asking you.",
            confirm = "Save", acl = target.acl, secrets = state.secrets,
            onConfirm = { acl ->
                controller.setMachineAcl(target.id, acl).also {
                    if (it == null) {
                        editingAcl = null
                        Thread { controller.sync() }.start()
                    }
                }
            },
            onCancel = { editingAcl = null },
        )
        is DeviceInfo -> AclSheet(
            title = "ACL for agents on ${target.name}",
            message = "What the agents on that Mac may use, through Mayi there and from your other devices.",
            confirm = "Save", acl = target.agentsAcl, secrets = state.secrets,
            onConfirm = { acl ->
                controller.setAgentsAcl(target.id, acl).also {
                    if (it == null) {
                        editingAcl = null
                        Thread { controller.sync() }.start()
                    }
                }
            },
            onCancel = { editingAcl = null },
        )
    }

    LazyColumn {
        if (controller.vaultIsEmpty) {
            item {
                Card(Modifier.fillMaxWidth().padding(16.dp)) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("This phone’s vault is empty", style = MaterialTheme.typography.titleSmall)
                        Text(
                            "If your secrets are on another device, join that vault instead. Mayi restarts into setup.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        OutlinedButton(onClick = { confirmJoin = true }) { Text("Join another vault") }
                    }
                }
            }
        }
        (error ?: state.syncStatus)?.let { status ->
            item {
                Text(
                    status, style = MaterialTheme.typography.bodySmall,
                    color = if (error != null) scheme.error else scheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                )
            }
        }
        item { SectionHeader("Hold your vault", "Each keeps a copy of your secrets. Phones and Macs also answer agents’ requests.") }
        items(state.devices.sortedBy { it.removed }, key = { it.id }) { device ->
            ListItem(
                leadingContent = {
                    Icon(
                        when {
                            device.recovery -> Icons.Outlined.Key
                            device.thisDevice -> Icons.Outlined.PhoneAndroid
                            else -> Icons.Outlined.Laptop
                        },
                        contentDescription = null,
                    )
                },
                headlineContent = { Text(if (device.thisDevice) "${device.name} (this phone)" else device.name) },
                supportingContent = {
                    Text(
                        when {
                            device.recovery -> "Kept offline by you"
                            device.addresses.isEmpty() -> "Has not said where it is yet"
                            else -> "At " + device.addresses.joinToString()
                        },
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                },
                modifier = if (device.removed) Modifier.alpha(0.55f) else Modifier,
                trailingContent = {
                    when {
                        device.removed -> Text("Removed", style = MaterialTheme.typography.labelMedium, color = scheme.onSurfaceVariant)
                        !device.thisDevice -> TextButton(onClick = { removing = device }) { Text("Remove", color = scheme.error) }
                    }
                },
            )
        }
        // Until there is one, a nudge: without it, losing every device loses the vault.
        if (state.devices.none { it.recovery && !it.removed }) {
            item {
                ListItem(
                    leadingContent = { Icon(Icons.Outlined.Key, contentDescription = null, tint = scheme.onSurfaceVariant) },
                    headlineContent = { Text("No recovery key yet", color = scheme.onSurfaceVariant) },
                    supportingContent = { Text("An offline key that restores the vault if you lose your devices. Tap to create one.") },
                    modifier = Modifier.clickable { createRecoveryKey() },
                )
            }
        }
        item { SectionHeader("Ask for secrets", "Agents get only what their ACL allows, and store nothing.") }
        items(agentDevices, key = { "agents:" + it.id }) { device ->
            ListItem(
                leadingContent = { Icon(Icons.Outlined.Laptop, contentDescription = null) },
                headlineContent = { Text("Agents on ${device.name}") },
                supportingContent = {
                    Column {
                        Text("Through Mayi on that Mac, and from there on your other devices")
                        device.agentsAcl?.let { AclLine(it) }
                    }
                },
                modifier = Modifier.clickable { editingAcl = device },
            )
        }
        if (paired.isEmpty()) {
            item {
                Text(
                    "No paired machine yet. Pair a server or a VM running agents with +.",
                    style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
        }
        items(paired, key = { it.id }) { machine ->
            ListItem(
                leadingContent = { Icon(Icons.Outlined.Dns, contentDescription = null) },
                headlineContent = { Text(machine.name) },
                supportingContent = {
                    Column {
                        Text("Key ${machine.id.take(8)}")
                        if (!machine.revoked) AclLine(machine.acl)
                    }
                },
                // A revoked machine is history, not something to act on.
                modifier = if (machine.revoked) Modifier.alpha(0.55f) else Modifier.clickable { editingAcl = machine },
                trailingContent = {
                    if (machine.revoked) {
                        Text("Revoked", style = MaterialTheme.typography.labelMedium, color = scheme.onSurfaceVariant)
                    } else {
                        TextButton(onClick = {
                            controller.revokeMachine(machine.id)
                            Thread { controller.sync() }.start()
                        }) { Text("Revoke", color = scheme.error) }
                    }
                },
            )
        }
        item {
            Text(
                "Mayi ${app.version}", style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 24.dp),
            )
        }
        // Room for the Add button to float without covering the last row.
        item { Spacer(Modifier.height(88.dp)) }
    }

    removing?.let { device ->
        AlertDialog(
            onDismissRequest = { removing = null },
            title = { Text("Remove ${device.name}?") },
            text = { Text("It stops syncing and answering for this vault. It keeps what it could already read, so Mayi lists the secrets to rotate.") },
            confirmButton = {
                TextButton(onClick = {
                    removing = null
                    controller.removeDevice(device.id)
                        .onSuccess { advice = rotationAdvice(it, "${device.name} could read") }
                        .onFailure { error = it.message }
                    Thread { controller.sync() }.start()
                }) { Text("Remove", color = scheme.error) }
            },
            dismissButton = { TextButton(onClick = { removing = null }) { Text("Cancel") } },
        )
    }
    advice?.let {
        AlertDialog(
            onDismissRequest = { advice = null },
            title = { Text("Removed") },
            text = { Text(it) },
            confirmButton = { TextButton(onClick = { advice = null }) { Text("OK") } },
        )
    }
    if (confirmJoin) {
        AlertDialog(
            onDismissRequest = { confirmJoin = false },
            title = { Text("Join another vault?") },
            text = { Text("This phone’s empty vault is set aside, and Mayi restarts into setup.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmJoin = false
                    error = activity?.let { app.setAsideEmptyVault(it) }
                }) { Text("Restart and join") }
            },
            dismissButton = { TextButton(onClick = { confirmJoin = false }) { Text("Cancel") } },
        )
    }
}

/** What the Add button on Devices adds: a machine that asks, or a device that holds the vault. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddChoice(onPair: () -> Unit, onDevice: () -> Unit, onRecovery: () -> Unit, onDismiss: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(bottom = 28.dp)) {
            Text("Add", style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp))
            ListItem(
                leadingContent = { Icon(Icons.Outlined.PhoneAndroid, contentDescription = null) },
                headlineContent = { Text("Add a device") },
                supportingContent = { Text("A phone or Mac of yours. It holds a copy of every secret and answers requests.") },
                modifier = Modifier.clickable(onClick = onDevice),
                colors = ListItemDefaults.colors(containerColor = Color.Transparent),
            )
            ListItem(
                leadingContent = { Icon(Icons.Outlined.Dns, contentDescription = null) },
                headlineContent = { Text("Pair a machine") },
                supportingContent = { Text("A server or VM running agents. It asks for the secrets you choose and stores none.") },
                modifier = Modifier.clickable(onClick = onPair),
                colors = ListItemDefaults.colors(containerColor = Color.Transparent),
            )
            ListItem(
                leadingContent = { Icon(Icons.Outlined.Key, contentDescription = null) },
                headlineContent = { Text("Create a recovery key") },
                supportingContent = { Text("Kept offline by you. It restores the vault if you lose your devices.") },
                modifier = Modifier.clickable(onClick = onRecovery),
                colors = ListItemDefaults.colors(containerColor = Color.Transparent),
            )
        }
    }
}

/** A section of Devices: what its rows do, in a line. */
@Composable
private fun SectionHeader(title: String, about: String) {
    Column(Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 24.dp, bottom = 4.dp)) {
        Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
        Text(about, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** "ACL: #ci, PROD_DB" under a machine; stronger when it is limited. */
@Composable
private fun AclLine(acl: AclRecord) {
    Text(
        "ACL: " + aclSummary(acl), maxLines = 2, overflow = TextOverflow.Ellipsis,
        color = if (acl.all) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.onSurface,
    )
}

// --- Activity ---------------------------------------------------------------------

/** How a secret came to be released, in the user's terms. */
private fun how(via: String) = when (via) {
    "level" -> "without asking"
    "allowlist" -> "as an expected command"
    "grant" -> "under an earlier approval"
    "approval" -> "with your approval"
    "biometric" -> "with your fingerprint"
    else -> via
}

private fun startOfDay(millis: Long): Long = Calendar.getInstance().apply {
    timeInMillis = millis
    set(Calendar.HOUR_OF_DAY, 0); set(Calendar.MINUTE, 0); set(Calendar.SECOND, 0); set(Calendar.MILLISECOND, 0)
}.timeInMillis

/** The agent, the machine it asked from, and which device answered when it was another one. */
private fun whoAndWhere(entry: AuditRecord): String = when {
    entry.remote && entry.device == null -> "${entry.agent}, from ${entry.requester}"
    entry.remote -> "${entry.agent}, from ${entry.requester}, answered on ${entry.device}"
    entry.device == null -> "${entry.agent}, on this phone"
    else -> "${entry.agent}, on ${entry.device}"
}

@Composable
private fun Activity(log: List<AuditRecord>) {
    val scheme = MaterialTheme.colorScheme
    if (log.isEmpty()) {
        EmptyState(Icons.Outlined.History, "No activity yet", "Every request is recorded here with its command or website and the reason given, whether it was allowed or not.")
        return
    }
    val time = remember { DateFormat.getTimeInstance(DateFormat.SHORT) }
    // Another device's withdrawn prompts are left out: the request shows where it was answered.
    val days = remember(log) {
        log.asReversed().filter { !(it.device != null && it.outcome == "withdrawn") }
            .groupBy { startOfDay(it.tsMs.toLong()) }.toList()
    }
    LazyColumn {
        for ((day, entries) in days) {
            item(key = "day$day") {
                Text(
                    DateUtils.getRelativeTimeSpanString(day, System.currentTimeMillis(), DateUtils.DAY_IN_MILLIS).toString(),
                    style = MaterialTheme.typography.titleSmall, color = scheme.primary,
                    modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 4.dp),
                )
            }
            items(entries) { entry ->
                val released = entry.outcome == "released"
                // Answered on another device, or the agent stopped waiting: not refused.
                val withdrawn = entry.outcome == "withdrawn"
                val request = entry.event == "request"
                val names = entry.secrets.joinToString { it.name }
                val signIn = entry.site.isNotEmpty()
                ListItem(
                    leadingContent = {
                        Icon(
                            when {
                                request && released -> Icons.Outlined.Key
                                request && withdrawn -> Icons.AutoMirrored.Outlined.Undo
                                request -> Icons.Outlined.Cancel
                                entry.event == "stop" -> Icons.Outlined.StopCircle
                                entry.event == "view" -> Icons.Outlined.Visibility
                                else -> Icons.Outlined.Check
                            },
                            contentDescription = null,
                            tint = when {
                                request && released || entry.event == "view" -> scheme.onSurface
                                entry.event == "exit" || withdrawn -> scheme.outline
                                else -> scheme.error
                            },
                        )
                    },
                    headlineContent = {
                        Text(
                            when {
                                request && released -> {
                                    val ways = entry.secrets.map { how(it.via) }.toSet()
                                    (if (signIn) "Typed $names into ${host(entry.site)}" else "Released $names") +
                                        if (ways.size == 1) " ${ways.first()}" else ""
                                }
                                request && withdrawn -> "Withdrawn: $names"
                                request -> if (names.isEmpty()) "Request refused" else "Refused $names"
                                entry.event == "stop" -> if (signIn) "Sign-in stopped by you" else "Command stopped by you"
                                entry.event == "view" -> "You viewed $names on ${entry.device ?: "this phone"}"
                                // A sign-in's "command" is the typing; its exit says whether that worked.
                                signIn -> if (entry.outcome == "exit 0") "Sign-in submitted" else "Sign-in not completed"
                                else -> "Command finished" + if (entry.outcome.startsWith("exit ")) ", ${entry.outcome}" else ""
                            },
                            color = if (entry.event == "exit") scheme.onSurfaceVariant else scheme.onSurface,
                        )
                    },
                    supportingContent = if (!request) null else {
                        {
                            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                if (withdrawn) {
                                    Text("Answered on another device, or the agent stopped waiting.", color = scheme.onSurfaceVariant)
                                } else if (!released) {
                                    Text(entry.outcome.removePrefix("denied: ").replaceFirstChar { it.uppercase() } + ".", color = scheme.error)
                                }
                                Text(if (signIn) entry.site else entry.command, fontFamily = FontFamily.Monospace, maxLines = 2, overflow = TextOverflow.Ellipsis)
                                Text("Reason given: “${entry.reason}”", maxLines = 2, overflow = TextOverflow.Ellipsis)
                                Text(whoAndWhere(entry), style = MaterialTheme.typography.bodySmall, color = scheme.outline)
                            }
                        }
                    },
                    trailingContent = { Text(time.format(Date(entry.tsMs.toLong()))) },
                )
            }
        }
    }
}
