package dev.mayi.android

import android.Manifest
import android.os.Build
import android.os.Bundle
import android.text.format.DateUtils
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import dev.mayi.ffi.ApprovalChoice
import dev.mayi.ffi.AuditRecord
import dev.mayi.ffi.PromptInfo
import dev.mayi.ffi.SecretRecord
import java.text.DateFormat
import java.util.Calendar
import java.util.Date

class MainActivity : FragmentActivity() {
    private val app get() = application as MayiApp

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        }
        setContent {
            MayiTheme {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    var ready by remember { mutableStateOf(app.hasVault) }
                    if (ready) Home(app, ::scan) else Setup(app, ::scan) { ready = true }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        app.foreground = this
    }

    override fun onPause() {
        app.foreground = null
        super.onPause()
    }

    private fun scan(onToken: (String) -> Unit) {
        GmsBarcodeScanning.getClient(this).startScan().addOnSuccessListener { code ->
            code.rawValue?.let(onToken)
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
            "In Mayi on a device that has your vault, choose Add a Device.",
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
        TextButton(onClick = { run { app.createVault() } }, enabled = !busy, modifier = Modifier.align(Alignment.CenterHorizontally)) {
            Text("No vault yet? Create one on this phone")
        }
        Spacer(Modifier.height(24.dp))
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
private fun Home(app: MayiApp, scan: ((String) -> Unit) -> Unit) {
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
                0 -> Requests(controller, state)
                1 -> Secrets(controller, state, adding, scan) { adding = it }
                2 -> Devices(controller, state, addingDevice, scan) { addingDevice = it }
                else -> Activity(state.log)
            }
        }
    }
}

// --- Requests ---------------------------------------------------------------------

@Composable
private fun Requests(controller: MayiController, state: MayiController.State) {
    if (state.pending.isEmpty() && state.notices.isEmpty()) {
        EmptyState(Icons.Outlined.Notifications, "Nothing is waiting for you", "When an agent needs your say, its request appears here.")
        return
    }
    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        items(state.pending, key = { "p${it.runId}" }) { prompt -> RequestCard(prompt) { controller.answer(prompt.runId, it) } }
        items(state.notices, key = { "n${it.notice.runId}" }) { active ->
            NoticeCard(active, onStop = { controller.stop(active.notice.runId) }, onDismiss = { controller.dismiss(active.notice.runId) })
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
    var deleting by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scheme = MaterialTheme.colorScheme

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
                    headlineContent = { Text(secret.name, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis) },
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
            AddSecret(scan = scan, onCancel = { setAdding(false) }) { draft ->
                val problem = controller.saveSecret(
                    draft.name, draft.level, draft.values, draft.allow, 900u, draft.login, draft.sites,
                )
                if (problem == null) {
                    Thread { controller.sync() }.start()
                    setAdding(false)
                }
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
                Spacer(Modifier.height(4.dp))
                OutlinedButton(
                    onClick = {
                        deleting = secret.name
                        detail = null
                    },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = scheme.error),
                ) { Text(if (secret.login) "Delete login" else "Delete secret") }
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

/** What the add sheet produces. */
private class NewSecret(
    val name: String, val level: UByte, val values: Map<String, String>, val allow: List<String>,
    val login: Boolean, val sites: List<String>,
)

private fun lines(text: String) = text.lines().map { it.trim() }.filter { it.isNotEmpty() }

/** Returns an error message from [onSave] to keep the sheet open and show it. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddSecret(scan: ((String) -> Unit) -> Unit, onCancel: () -> Unit, onSave: (NewSecret) -> String?) {
    var login by remember { mutableStateOf(false) }
    var name by remember { mutableStateOf("") }
    var value by remember { mutableStateOf("") }
    var allow by remember { mutableStateOf("") }
    var sites by remember { mutableStateOf("") }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var twoFactor by remember { mutableStateOf("") }
    var level by remember { mutableIntStateOf(3) }
    var error by remember { mutableStateOf<String?>(null) }
    val scheme = MaterialTheme.colorScheme
    val mono = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace)
    val secretField = @Composable { text: String, set: (String) -> Unit, label: String, trailing: (@Composable () -> Unit)? ->
        OutlinedTextField(
            text, set, Modifier.fillMaxWidth(), label = { Text(label) }, singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = trailing,
        )
    }
    Column(
        Modifier.padding(horizontal = 24.dp).padding(bottom = 24.dp).imePadding().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(if (login) "New login" else "New secret", style = MaterialTheme.typography.titleLarge)
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
        if (login) {
            OutlinedTextField(
                sites, { sites = it }, Modifier.fillMaxWidth(), label = { Text("Websites, one per line") },
                placeholder = { Text("github.com") }, textStyle = mono, minLines = 1,
                supportingText = { Text("As the address bar shows them. *.example.com covers its subdomains. Typed into these sites only, over https.") },
            )
            OutlinedTextField(username, { username = it }, Modifier.fillMaxWidth(), label = { Text("Username (optional)") }, singleLine = true)
            secretField(password, { password = it }, "Password", null)
            secretField(twoFactor, { twoFactor = it }, "Two-factor key (optional)") {
                IconButton(onClick = { scan { twoFactor = it } }) {
                    Icon(Icons.Outlined.QrCodeScanner, contentDescription = "Scan the site’s QR code")
                }
            }
            Text(
                "The two-factor key is what a site shows when you turn on an authenticator app: scan its QR code, or paste the key. It stays on your devices; a page only ever gets the current code.",
                style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant,
            )
        } else {
            secretField(value, { value = it }, "Value", null)
        }
        Column {
            Text("Level", style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(bottom = 4.dp))
            for (step in 1..4) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .selectable(selected = level == step, role = Role.RadioButton, onClick = { level = step })
                        .padding(vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    RadioButton(selected = level == step, onClick = null)
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
                    val draft = if (login) {
                        val values = buildMap {
                            put("password", password)
                            if (username.isNotBlank()) put("username", username.trim())
                            if (twoFactor.isNotBlank()) put("totp", twoFactor.trim())
                        }
                        NewSecret(name.trim(), level.toUByte(), values, emptyList(), true, lines(sites))
                    } else {
                        NewSecret(name.trim(), level.toUByte(), mapOf("value" to value), lines(allow), false, emptyList())
                    }
                    error = onSave(draft)
                },
                enabled = name.isNotBlank() && if (login) password.isNotEmpty() && sites.isNotBlank() else value.isNotEmpty(),
            ) { Text(if (login) "Add login" else "Add secret") }
        }
    }
}

// --- Devices ----------------------------------------------------------------------

/**
 * Adding a device: the new one shows a code while it has no vault (a Mac in
 * its setup window), and this phone scans it or takes it as text.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddDevice(controller: MayiController, scan: ((String) -> Unit) -> Unit, onClose: () -> Unit) {
    var code by remember { mutableStateOf("") }
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
    ModalBottomSheet(onDismissRequest = { if (!busy) onClose() }, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(
            Modifier.padding(horizontal = 24.dp).padding(bottom = 28.dp).imePadding().verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text("Add a device", style = MaterialTheme.typography.titleLarge)
            val name = added
            if (name != null) {
                Text("$name was added. It now holds a copy of every secret and can answer requests.", style = MaterialTheme.typography.bodyLarge)
                Row {
                    Spacer(Modifier.weight(1f))
                    Button(onClick = onClose) { Text("Done") }
                }
                return@Column
            }
            Text(
                "Start setting up Mayi on the new device. A Mac shows a code under Join Your Vault: scan it here.",
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
                Text("Adding. If you have level 4 secrets, confirm with your fingerprint.", style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant)
            }
            error?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = scheme.error) }
            Text(
                "The new device receives the whole vault, so add only a device you own.",
                style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Spacer(Modifier.weight(1f))
                TextButton(onClick = onClose, enabled = !busy) { Text("Cancel") }
                Button(onClick = { add(code) }, enabled = !busy && code.isNotBlank()) { Text("Add") }
            }
        }
    }
}

@Composable
private fun Devices(
    controller: MayiController, state: MayiController.State, adding: Boolean, scan: ((String) -> Unit) -> Unit,
    setAdding: (Boolean) -> Unit,
) {
    val scheme = MaterialTheme.colorScheme
    if (adding) AddDevice(controller, scan) { setAdding(false) }
    LazyColumn {
        state.syncStatus?.let { status ->
            item { Text(status, style = MaterialTheme.typography.bodySmall, color = scheme.onSurfaceVariant, modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)) }
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
                trailingContent = { if (device.removed) Text("Removed", color = scheme.error) },
            )
        }
        item {
            Text(
                "Machines", style = MaterialTheme.typography.titleSmall, color = scheme.primary,
                modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 24.dp, bottom = 8.dp),
            )
        }
        if (state.machines.isEmpty()) {
            item {
                Text(
                    "None yet. Pair machines from Mayi on your Mac.",
                    style = MaterialTheme.typography.bodyMedium, color = scheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
        }
        items(state.machines, key = { it.id }) { machine ->
            ListItem(
                leadingContent = { Icon(Icons.Outlined.Dns, contentDescription = null) },
                headlineContent = { Text(machine.name) },
                supportingContent = { Text("Key ${machine.id.take(8)}") },
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
                                else -> Icons.Outlined.Check
                            },
                            contentDescription = null,
                            tint = when {
                                request && released -> scheme.onSurface
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
