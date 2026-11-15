package dev.mayi.android

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.format.DateUtils
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
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
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import dev.mayi.ffi.ApprovalChoice
import dev.mayi.ffi.AuditRecord
import dev.mayi.ffi.DeviceInfo
import dev.mayi.ffi.JoinInvitation
import dev.mayi.ffi.PromptInfo
import dev.mayi.ffi.RevealedSecret
import dev.mayi.ffi.SecretRecord
import java.text.DateFormat
import java.util.Calendar
import java.util.Date

class MainActivity : FragmentActivity() {
    private val app get() = application as MayiApp
    /** Bumped on every resume, so screens re-check settings changed meanwhile. */
    private val resumes = androidx.compose.runtime.mutableIntStateOf(0)
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
        app.ensureServing()
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
                        else -> Home(app, ::scan, resumes)
                    }
                    scanning.value?.let { onToken ->
                        BackHandler { scanning.value = null }
                        QrScanner(this@MainActivity, onCode = {
                            scanning.value = null
                            onToken(it)
                        }, onCancel = { scanning.value = null })
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        resumes.intValue++
        app.foreground = this
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
            "On a Mac with your vault: Devices, Add a Device. On a phone: Devices, Add device, Show an invitation.",
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
            "On a phone with your vault: Devices, Add device, Scan its code. On a Mac: Devices, Add a Device, then paste the code.",
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
private fun Home(app: MayiApp, scan: ((String) -> Unit) -> Unit, resumes: MutableIntState) {
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
                ExtendedFloatingActionButton(
                    onClick = { addingDevice = true },
                    icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                    text = { Text("Add device") },
                )
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
        if (state.pending.isEmpty() && state.notices.isEmpty()) {
            EmptyState(Icons.Outlined.Notifications, "Nothing is waiting for you", "When an agent needs your say, its request appears here.")
            return@Column
        }
        LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
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
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        when {
                            site != null -> "Allow signing in to ${host(site)}?"
                            needed.size == 1 -> "Allow this command to use ${needed[0].name}?"
                            else -> "Allow this command to use ${needed.size} secrets?"
                        },
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(origin(prompt.request), style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant)
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
                Text(
                    when {
                        active.stopped -> "Stopped, and its session revoked"
                        active.ended -> if (site != null) "Sign-in done" else "Command finished"
                        else -> origin(active.notice.request)
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = scheme.onSurfaceVariant,
                )
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
                if (secret.level < 4u && !app.authenticate("Show ${secret.name}")) {
                    Result.failure(IllegalStateException("Showing values needs your fingerprint."))
                } else {
                    controller.reveal(secret.name)
                },
            )
        }.start()
    }

    if (state.secrets.isEmpty()) {
        EmptyState(Icons.Outlined.Key, "No secrets yet", "Add an API key, a token or a website login. An agent then uses it by name and never sees the value.")
    } else {
        LazyColumn {
            error?.let { message ->
                item { Text(message, style = MaterialTheme.typography.bodyMedium, color = scheme.error, modifier = Modifier.padding(horizontal = 16.dp)) }
            }
            items(state.secrets, key = { it.name }) { secret ->
                ListItem(
                    leadingContent = {
                        Icon(
                            if (secret.login) Icons.Outlined.Language else Icons.Outlined.Key,
                            contentDescription = if (secret.login) "Website login" else "Secret",
                        )
                    },
                    headlineContent = {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text(
                                secret.name, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f, fill = false),
                            )
                            if (secret.copies < 2u) OneCopyDot()
                        }
                    },
                    supportingContent = { Text(summary(secret), maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    trailingContent = { LevelLabel(secret.level.toInt()) },
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
            AddSecret(scan = scan, existing = null, onCancel = { setAdding(false) }) { draft ->
                val problem = save(controller, draft)
                if (problem == null) setAdding(false)
                problem
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
            ) { draft ->
                val problem = save(controller, draft)
                if (problem == null) editing = null
                problem
            }
        }
    }
    detail?.let { secret ->
        ModalBottomSheet(onDismissRequest = { detail = null }) {
            Column(
                Modifier.padding(horizontal = 24.dp).padding(bottom = 28.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(secret.name, style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace)
                LevelLabel(secret.level.toInt(), color = scheme.onSurface)
                Text(
                    (if (secret.login) loginLevelDetails else levelDetails)[secret.level.toInt() - 1],
                    style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant,
                )
                Text(summary(secret) + ".", style = MaterialTheme.typography.bodyMedium)
                if (secret.copies < 2u) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OneCopyDot()
                        Text(
                            "Only on this phone. It reaches your other devices when they next sync; add a device to keep a second copy.",
                            style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant,
                        )
                    }
                }
                Spacer(Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
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
    val maxGrantSecs: ULong, val login: Boolean, val sites: List<String>,
)

private fun lines(text: String) = text.lines().map { it.trim() }.filter { it.isNotEmpty() }

/** Stores a draft: new values, or only the rules when no value was entered. */
private fun save(controller: MayiController, draft: NewSecret): String? {
    val problem = if (draft.values.isEmpty()) {
        controller.updateRules(draft.name, draft.allow, draft.maxGrantSecs, draft.sites)
    } else {
        controller.saveSecret(draft.name, draft.level, draft.values, draft.allow, draft.maxGrantSecs, draft.login, draft.sites)
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
    onSave: (NewSecret) -> String?,
) {
    val editing = existing != null
    var login by remember { mutableStateOf(existing?.login ?: false) }
    var name by remember { mutableStateOf(existing?.name ?: "") }
    var value by remember { mutableStateOf("") }
    var allow by remember { mutableStateOf(existing?.allow?.joinToString("\n") ?: "") }
    var sites by remember { mutableStateOf(existing?.sites?.joinToString("\n") ?: "") }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var twoFactor by remember { mutableStateOf("") }
    var level by remember { mutableIntStateOf(existing?.level?.toInt() ?: 3) }
    var maxGrant by remember { mutableStateOf(existing?.maxGrantSecs ?: 900uL) }
    var error by remember { mutableStateOf<String?>(null) }
    val scheme = MaterialTheme.colorScheme
    val mono = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace)
    val context = LocalContext.current
    val severalFields = existing != null && !existing.login && existing.fields != listOf("value")
    /** The stored values, once shown: saving them unchanged changes only the rules. */
    var shown by remember { mutableStateOf<Map<String, String>?>(null) }
    val fieldValues = remember { mutableStateMapOf<String, String>() }
    /** A login's current two-factor code, and until when it is valid. */
    var code by remember { mutableStateOf<Pair<String, Long>?>(null) }
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
                    existing?.login == true -> {
                        username = values["username"] ?: ""
                        password = values["password"] ?: ""
                        twoFactor = values["totp"] ?: ""
                    }
                    severalFields -> {
                        fieldValues.clear()
                        fieldValues.putAll(values)
                    }
                    else -> value = values["value"] ?: ""
                }
                code = revealed.code?.let { it to System.currentTimeMillis() + revealed.codeValidSecs.toLong() * 1000 }
                shown = values
            }.onFailure { error = MayiController.describe(it) }
        }
    }
    LaunchedEffect(Unit) { if (revealOnOpen) showValues() }
    val keep = if (editing && shown == null) "unchanged" else null
    val copy = @Composable { text: String ->
        IconButton(onClick = { copySecret(context, text) }, enabled = text.isNotEmpty()) {
            Icon(Icons.Outlined.ContentCopy, contentDescription = "Copy")
        }
    }
    val secretField = @Composable { text: String, set: (String) -> Unit, label: String, trailing: (@Composable () -> Unit)? ->
        // Hidden while typing a new value; readable, with a copy button, once shown.
        val visible = shown != null
        OutlinedTextField(
            text, set, Modifier.fillMaxWidth(), label = { Text(label) }, singleLine = true,
            placeholder = keep?.let { hint -> { Text(hint) } },
            visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
            textStyle = if (visible) mono else MaterialTheme.typography.bodyLarge,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = if (visible) ({ copy(text) }) else trailing,
        )
    }
    val showButton = @Composable {
        if (editing && reveal != null && shown == null) {
            OutlinedButton(onClick = ::showValues, enabled = !revealing) {
                Icon(Icons.Outlined.Visibility, contentDescription = null, modifier = Modifier.size(ButtonDefaults.IconSize))
                Spacer(Modifier.width(ButtonDefaults.IconSpacing))
                Text(if (revealing) "Waiting for you…" else "Show values")
            }
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
                login -> "New login"
                else -> "New secret"
            },
            style = MaterialTheme.typography.titleLarge,
        )
        if (!editing) {
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                listOf(false to "Secret", true to "Website login").forEachIndexed { index, (isLogin, label) ->
                    SegmentedButton(
                        selected = login == isLogin, onClick = { login = isLogin },
                        shape = SegmentedButtonDefaults.itemShape(index, 2),
                    ) { Text(label) }
                }
            }
            OutlinedTextField(
                name, { name = it }, Modifier.fillMaxWidth(), label = { Text("Name") },
                placeholder = { Text(if (login) "github" else "GITHUB_TOKEN") }, textStyle = mono, singleLine = true,
            )
        }
        if (login) {
            OutlinedTextField(
                sites, { sites = it }, Modifier.fillMaxWidth(), label = { Text("Websites, one per line") },
                placeholder = { Text("github.com") }, textStyle = mono, minLines = 1,
                supportingText = { Text("As the address bar shows them. *.example.com covers its subdomains. Typed into these sites only, over https.") },
            )
            OutlinedTextField(
                username, { username = it }, Modifier.fillMaxWidth(), label = { Text("Username (optional)") }, singleLine = true,
                placeholder = keep?.let { hint -> { Text(hint) } },
                trailingIcon = if (shown != null) ({ copy(username) }) else null,
            )
            secretField(password, { password = it }, "Password", null)
            secretField(twoFactor, { twoFactor = it }, "Two-factor key (optional)") {
                IconButton(onClick = { scan { twoFactor = it } }) {
                    Icon(Icons.Outlined.QrCodeScanner, contentDescription = "Scan the site’s QR code")
                }
            }
            code?.let { (current, until) -> CurrentCode(current, until, copy, onExpired = ::showValues) }
            showButton()
            Text(
                when {
                    shown != null -> shownHint
                    editing -> "Leave all three empty to keep what is stored, or show them to read and edit them. Changing the level needs the password again."
                    else -> "The two-factor key is what a site shows when you turn on an authenticator app: scan its QR code, or paste the key. It stays on your devices; a page only ever gets the current code."
                },
                style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant,
            )
        } else if (severalFields) {
            if (shown == null) {
                Text(
                    "This secret holds ${existing?.fields?.joinToString()}. Show its values to read and edit them.",
                    style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant,
                )
                showButton()
            } else {
                for (field in existing?.fields.orEmpty()) {
                    secretField(fieldValues[field] ?: "", { fieldValues[field] = it }, field, null)
                }
                Text(shownHint, style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant)
            }
        } else {
            secretField(value, { value = it }, "Value", null)
            showButton()
            if (editing) {
                Text(
                    if (shown != null) shownHint
                    else "Leave empty to keep what is stored, or show it to read and edit it. Changing the level needs the value again.",
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
                            if (twoFactor.isNotBlank()) put("totp", twoFactor.trim())
                        }
                        severalFields && shown == null -> emptyMap()
                        severalFields -> fieldValues.toMap()
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
                            "Changing the level re-encrypts it, so enter its " + (if (login) "password" else "value") + " again."
                        else -> onSave(
                            NewSecret(
                                name.trim(), level.toUByte(), values, if (login) emptyList() else lines(allow), maxGrant, login,
                                if (login) lines(sites) else emptyList(),
                            ),
                        )
                    }
                },
            ) { Text(if (editing) "Save" else if (login) "Add login" else "Add secret") }
        }
    }
}

/** A login's two-factor code, counting down; once expired, a way to show the next one. */
@Composable
private fun CurrentCode(current: String, until: Long, copy: @Composable (String) -> Unit, onExpired: () -> Unit) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(until) {
        while (now < until) {
            kotlinx.coroutines.delay(1000)
            now = System.currentTimeMillis()
        }
    }
    val left = ((until - now + 999) / 1000).toInt()
    if (left > 0) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Code now", style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Text(current, style = MaterialTheme.typography.titleMedium, fontFamily = FontFamily.Monospace)
            Text(
                "  for $left s", style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            copy(current)
        }
    } else {
        TextButton(onClick = onExpired) { Text("Show the next code") }
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
            if (!app.authenticate("Add a device that will hold all your secrets")) {
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

/** An invitation for a machine to pair: a command to run there. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PairMachine(app: MayiApp, controller: MayiController, state: MayiController.State, onClose: () -> Unit) {
    var token by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    DisposableEffect(Unit) {
        Thread {
            if (!app.authenticate("Allow another machine to request secrets")) {
                error = "Pairing needs your fingerprint."
            } else {
                controller.startPairing(600u).onSuccess { token = it }.onFailure { error = it.message }
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

    if (adding) AddDevice(app, controller, state, scan) { setAdding(false) }
    if (pairing) PairMachine(app, controller, state) { pairing = false }
    recoveryKey?.let { RecoveryKey(it) { recoveryKey = null } }

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
        items(state.devices, key = { it.id }) { device ->
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
                trailingContent = {
                    when {
                        device.removed -> Text("Removed", color = scheme.error)
                        !device.thisDevice -> TextButton(onClick = { removing = device }) { Text("Remove", color = scheme.error) }
                    }
                },
            )
        }
        item {
            ListItem(
                leadingContent = { Icon(Icons.Outlined.Key, contentDescription = null) },
                headlineContent = { Text("Create recovery key") },
                supportingContent = { Text("An offline key that restores the vault if your devices’ keys are lost") },
                modifier = Modifier.clickable {
                    Thread {
                        if (!app.authenticate("Create a key that can open your vault without this phone")) {
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
                },
            )
        }
        item {
            Row(
                Modifier.fillMaxWidth().padding(start = 16.dp, end = 8.dp, top = 24.dp, bottom = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Machines", style = MaterialTheme.typography.titleSmall, color = scheme.primary, modifier = Modifier.weight(1f))
                TextButton(onClick = { pairing = true }) { Text("Pair a machine") }
            }
        }
        if (state.machines.isEmpty()) {
            item {
                Text(
                    "None yet. A paired machine, such as a server or a VM running agents, asks this vault for secrets and stores none.",
                    style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
        }
        items(state.machines, key = { it.id }) { machine ->
            ListItem(
                leadingContent = { Icon(Icons.Outlined.Dns, contentDescription = null) },
                headlineContent = { Text(machine.name) },
                supportingContent = {
                    // A machine that holds a vault device and paired itself through it.
                    Text(machine.runsDevice?.let { "Agents on $it. Key ${machine.id.take(8)}" } ?: "Key ${machine.id.take(8)}")
                },
                trailingContent = {
                    if (machine.revoked) {
                        Text("Revoked", color = scheme.error)
                    } else {
                        TextButton(onClick = {
                            controller.revokeMachine(machine.id)
                            Thread { controller.sync() }.start()
                        }) { Text("Revoke", color = scheme.error) }
                    }
                },
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

@Composable
private fun Activity(log: List<AuditRecord>) {
    val scheme = MaterialTheme.colorScheme
    if (log.isEmpty()) {
        EmptyState(Icons.Outlined.History, "No activity yet", "Every request is recorded here with its command or website and the reason given, whether it was allowed or not.")
        return
    }
    val time = remember { DateFormat.getTimeInstance(DateFormat.SHORT) }
    val days = remember(log) { log.asReversed().groupBy { startOfDay(it.tsMs.toLong()) }.toList() }
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
                val request = entry.event == "request"
                val names = entry.secrets.joinToString { it.name }
                val signIn = entry.site.isNotEmpty()
                ListItem(
                    leadingContent = {
                        Icon(
                            when {
                                request && released -> Icons.Outlined.Key
                                request -> Icons.Outlined.Cancel
                                entry.event == "stop" -> Icons.Outlined.StopCircle
                                entry.event == "view" -> Icons.Outlined.Visibility
                                else -> Icons.Outlined.Check
                            },
                            contentDescription = null,
                            tint = when {
                                request && released || entry.event == "view" -> scheme.onSurface
                                entry.event == "exit" -> scheme.outline
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
                                request -> if (names.isEmpty()) "Request refused" else "Refused $names"
                                entry.event == "stop" -> if (signIn) "Sign-in stopped by you" else "Command stopped by you"
                                entry.event == "view" -> "You viewed $names on this phone"
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
                                if (!released) {
                                    Text(entry.outcome.removePrefix("denied: ").replaceFirstChar { it.uppercase() } + ".", color = scheme.error)
                                }
                                Text(if (signIn) entry.site else entry.command, fontFamily = FontFamily.Monospace, maxLines = 2, overflow = TextOverflow.Ellipsis)
                                Text("Reason given: “${entry.reason}”", maxLines = 2, overflow = TextOverflow.Ellipsis)
                                Text(
                                    "${entry.agent}, " + if (entry.remote) "from ${entry.requester}" else "on this phone",
                                    style = MaterialTheme.typography.bodySmall, color = scheme.outline,
                                )
                            }
                        }
                    },
                    trailingContent = { Text(time.format(Date(entry.tsMs.toLong()))) },
                )
            }
        }
    }
}
