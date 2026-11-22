package dev.mayi.android

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.addPathNodes
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.mayi.ffi.AwsProfileRecord
import dev.mayi.ffi.AwsSession
import dev.mayi.ffi.AwsSignInFlow
import dev.mayi.ffi.AwsSignInNeededInfo
import dev.mayi.ffi.SecretRecord
import dev.mayi.ffi.awsSuggestProfiles
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private val awsOrange = Color(0xFFFF9900)

/**
 * What a level means for one role of an AWS sign-in. Level 4 is a fingerprint
 * for every use: the sign-in serves all its roles, so it cannot be encrypted
 * to the fingerprint for one of them.
 */
val awsLevelDetails = listOf(
    "Used without asking, and recorded in Activity.",
    "Used at once. You are notified and can stop the command.",
    "Each command waits for your approval.",
    "Your fingerprint for every use.",
)

/** The AWS logo: the wordmark in the text colour, the smile in AWS orange. */
@Composable
fun AwsLogo(modifier: Modifier = Modifier.size(width = 30.dp, height = 18.dp)) {
    val ink = MaterialTheme.colorScheme.onSurface
    val logo = remember(ink) {
        ImageVector.Builder("aws", 304.dp, 182.dp, 304f, 182f)
            .addPath(addPathNodes(AwsLogoPaths.WORDMARK), PathFillType.EvenOdd, fill = SolidColor(ink))
            .apply {
                AwsLogoPaths.SMILE.forEach { addPath(addPathNodes(it), PathFillType.EvenOdd, fill = SolidColor(awsOrange)) }
            }
            .build()
    }
    Image(logo, contentDescription = "AWS", modifier = modifier)
}

/** A role of an AWS sign-in, being chosen or edited. */
data class ProfileDraft(
    val enabled: Boolean, val name: String, val accountId: String, val accountName: String, val role: String, val level: Int,
) {
    constructor(p: AwsProfileRecord, enabled: Boolean = true) :
        this(enabled, p.name, p.accountId, p.accountName, p.role, p.level.toInt())

    val key get() = "$accountId/$role"

    fun record() = AwsProfileRecord(name = name, accountId = accountId, accountName = accountName, role = role, level = level.toUByte())
}

/** A name for a sign-in from its portal: `mawaqit` for https://mawaqit.awsapps.com/start. */
fun awsName(startUrl: String): String {
    val host = runCatching { Uri.parse(startUrl.trim()).host }.getOrNull() ?: return ""
    val first = host.substringBefore('.')
    val name = if (first.startsWith("d-")) "aws" else first
    return name.lowercase().map { if (it.isLetterOrDigit() || it == '-') it else '-' }.joinToString("")
}

private fun open(context: Context, url: String) {
    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}

/** The level of one role: its label, and a menu of the four with what each means. */
@Composable
private fun LevelChoice(level: Int, enabled: Boolean, onPick: (Int) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        TextButton(onClick = { open = true }, enabled = enabled) { LevelLabel(level) }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            (1..4).forEach { step ->
                DropdownMenuItem(
                    text = {
                        Column {
                            LevelLabel(step, color = MaterialTheme.colorScheme.onSurface)
                            Text(awsLevelDetails[step - 1], style = MaterialTheme.typography.bodySmall)
                        }
                    },
                    onClick = { onPick(step); open = false },
                )
            }
        }
    }
}

/** The roles of a sign-in, by account: a check box, the profile name agents use, and its level. */
@Composable
private fun ProfileList(profiles: SnapshotStateList<ProfileDraft>, signInName: String) {
    val accounts = profiles.map { it.accountId to it.accountName }.distinct()
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        accounts.forEach { (id, name) ->
            Text(
                if (name.isEmpty()) id else "$name · $id",
                style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(top = 8.dp),
            )
            profiles.forEachIndexed { index, p ->
                if (p.accountId != id) return@forEachIndexed
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(p.enabled, { profiles[index] = p.copy(enabled = it) })
                    Column(Modifier.weight(1f)) {
                        Text(p.role, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
                        OutlinedTextField(
                            p.name, { profiles[index] = p.copy(name = it.trim()) },
                            prefix = { Text("$signInName/") }, singleLine = true, enabled = p.enabled,
                            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    LevelChoice(p.level, p.enabled) { profiles[index] = p.copy(level = it) }
                }
            }
        }
    }
}

/** While the owner approves in the browser: the code to compare, and what to check. */
@Composable
private fun Waiting(flow: AwsSignInFlow, onCancel: () -> Unit) {
    val context = LocalContext.current
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Finish in your browser", style = MaterialTheme.typography.titleMedium)
        Text("AWS’s page is open. Sign in as you usually do, check it shows this code, then allow Mayi.")
        Text(
            flow.userCode(), style = MaterialTheme.typography.headlineMedium, fontFamily = FontFamily.Monospace,
            modifier = Modifier.align(Alignment.CenterHorizontally),
        )
        Text(
            "The page names the app asking. If a page like it ever names another app, an agent may have started it: don’t allow it.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
            Text("Waiting for AWS…", color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { open(context, flow.verificationUrl()) }) { Text("Open the page again") }
            TextButton(onClick = onCancel) { Text("Cancel") }
        }
    }
    DisposableEffect(flow) { onDispose { flow.cancel() } }
}

private sealed interface Step {
    data object Portal : Step
    class Signing(val flow: AwsSignInFlow) : Step
    class Choosing(val session: AwsSession) : Step
}

private const val CANCELLED = "the sign-in was cancelled"

/**
 * Adds an AWS sign-in: the portal, AWS's own sign-in in the browser, then
 * which roles agents may use and at which level. Shown in the Add sheet when
 * AWS sign-in is picked.
 */
@Composable
fun AwsSignInForm(controller: MayiController, folder: String?, onCancel: () -> Unit, onDone: () -> Unit) {
    val context = LocalContext.current
    var step by remember { mutableStateOf<Step>(Step.Portal) }
    var startUrl by remember { mutableStateOf("") }
    var region by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var nameEdited by remember { mutableStateOf(false) }
    val profiles = remember { mutableStateListOf<ProfileDraft>() }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var begin by remember { mutableStateOf(false) }
    var save by remember { mutableStateOf<AwsSession?>(null) }

    LaunchedEffect(begin) {
        if (!begin) return@LaunchedEffect
        busy = true
        error = null
        withContext(Dispatchers.IO) { controller.beginAwsSignIn(startUrl, region) }
            .onSuccess { flow -> open(context, flow.verificationUrl()); step = Step.Signing(flow) }
            .onFailure { error = MayiController.describe(it) }
        busy = false
        begin = false
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        when (val current = step) {
            Step.Portal -> {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    AwsLogo(Modifier.size(width = 40.dp, height = 24.dp))
                    Text(
                        "Mayi signs in to your AWS access portal itself and keeps the session on your devices. Agents never see it: they get one role’s temporary keys, at the level you choose for that role.",
                        style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                OutlinedTextField(
                    startUrl, { startUrl = it; if (!nameEdited) name = awsName(it) }, Modifier.fillMaxWidth(),
                    label = { Text("Start URL") }, placeholder = { Text("https://example.awsapps.com/start") }, singleLine = true,
                )
                OutlinedTextField(
                    region, { region = it.trim() }, Modifier.fillMaxWidth(),
                    label = { Text("Region") }, placeholder = { Text("eu-west-1") }, singleLine = true,
                )
                OutlinedTextField(
                    name, { name = it.trim(); nameEdited = true }, Modifier.fillMaxWidth(),
                    label = { Text("Name") }, placeholder = { Text("work") }, singleLine = true,
                    supportingText = { Text("Agents ask for a role as ${name.ifEmpty { "NAME" }}/PROFILE.") },
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.weight(1f))
                    TextButton(onClick = onCancel) { Text("Cancel") }
                    Button(
                        onClick = { begin = true },
                        enabled = !busy && startUrl.isNotBlank() && region.isNotBlank() && name.isNotBlank(),
                    ) { Text("Sign in with AWS") }
                }
            }
            is Step.Signing -> {
                Waiting(current.flow) { current.flow.cancel() }
                LaunchedEffect(current.flow) {
                    val session = withContext(Dispatchers.IO) { controller.finishAwsSignIn(current.flow) }
                    session.onSuccess { s ->
                        withContext(Dispatchers.IO) { controller.awsAccounts(s) }
                            .onSuccess { accounts ->
                                profiles.clear()
                                profiles.addAll(awsSuggestProfiles(accounts).map { ProfileDraft(it) })
                                step = Step.Choosing(s)
                            }
                            .onFailure { error = MayiController.describe(it); step = Step.Portal }
                    }.onFailure {
                        val why = MayiController.describe(it)
                        error = if (why == CANCELLED) null else why
                        step = Step.Portal
                    }
                }
            }
            is Step.Choosing -> {
                Text("Choose what agents may use", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Each role is a profile with its own level. Suggested: read-only roles at 1, roles that can change production at 4, the rest at 3.",
                    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                ProfileList(profiles, name)
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.weight(1f))
                    TextButton(onClick = onCancel) { Text("Cancel") }
                    Button(onClick = { save = current.session }, enabled = !busy && profiles.any { it.enabled }) { Text("Add sign-in") }
                }
                LaunchedEffect(save) {
                    val session = save ?: return@LaunchedEffect
                    busy = true
                    error = null
                    val chosen = profiles.filter { it.enabled }.map { it.record() }
                    val problem = withContext(Dispatchers.IO) { controller.saveAwsSignIn(name, session, chosen, folder) }
                    busy = false
                    save = null
                    if (problem == null) {
                        Thread { controller.sync() }.start()
                        onDone()
                    } else {
                        error = problem
                    }
                }
            }
        }
    }
}

/**
 * A saved AWS sign-in: its roles and their levels, more roles, signing in
 * again. Asking less of a role, or adding one, asks for a fingerprint.
 */
@Composable
fun AwsSignInEditor(controller: MayiController, secret: SecretRecord, onDone: () -> Unit) {
    val context = LocalContext.current
    val aws = secret.aws ?: return
    val original = remember(secret) { aws.profiles.map { ProfileDraft(it) } }
    val profiles = remember(secret) { mutableStateListOf<ProfileDraft>().apply { addAll(original) } }
    var signing by remember { mutableStateOf<AwsSignInFlow?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var action by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(action) {
        when (action) {
            "save" -> {
                busy = true
                error = null
                val chosen = profiles.filter { it.enabled }.map { it.record() }
                val problem = withContext(Dispatchers.IO) { controller.updateAwsProfiles(secret.name, chosen) }
                busy = false
                if (problem == null) {
                    Thread { controller.sync() }.start()
                    onDone()
                } else {
                    error = problem
                }
            }
            "roles" -> {
                busy = true
                error = null
                withContext(Dispatchers.IO) { controller.awsAccounts(secret.name) }
                    .onSuccess { accounts ->
                        val known = profiles.map { it.key }.toSet()
                        val found = awsSuggestProfiles(accounts).map { ProfileDraft(it, enabled = false) }.filter { it.key !in known }
                        profiles.addAll(found)
                        message = if (found.isEmpty()) "No new roles." else "Found ${found.size} new role(s): check the ones agents may use."
                    }
                    .onFailure { error = MayiController.describe(it) }
                busy = false
            }
            "signin" -> {
                busy = true
                error = null
                withContext(Dispatchers.IO) { controller.beginAwsSignIn(aws.startUrl, aws.region) }
                    .onSuccess { flow -> open(context, flow.verificationUrl()); signing = flow }
                    .onFailure { error = MayiController.describe(it) }
                busy = false
            }
        }
        action = null
    }

    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            AwsLogo(Modifier.size(width = 40.dp, height = 24.dp))
            Column {
                Text(secret.name, style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace)
                Text("${aws.startUrl} · ${aws.region}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        val flow = signing
        if (flow != null) {
            Waiting(flow) { flow.cancel() }
            LaunchedEffect(flow) {
                withContext(Dispatchers.IO) { controller.finishAwsSignIn(flow) }
                    .onSuccess { session ->
                        val problem = withContext(Dispatchers.IO) { controller.renewAwsSignIn(secret.name, session) }
                        if (problem == null) message = "Signed in again." else error = problem
                    }
                    .onFailure { val why = MayiController.describe(it); if (why != CANCELLED) error = why }
                signing = null
            }
            return@Column
        }
        ProfileList(profiles, secret.name)
        HorizontalDivider()
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { action = "roles" }, enabled = !busy) { Text("Find more roles") }
            OutlinedButton(onClick = { action = "signin" }, enabled = !busy) { Text("Sign in again") }
        }
        message?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
            Spacer(Modifier.weight(1f))
            Button(onClick = { action = "save" }, enabled = !busy && profiles.toList() != original) { Text("Save") }
        }
    }
}

/**
 * On the Requests tab: an AWS session ended while a command needed it.
 * Signing in again here lets the waiting command carry on.
 */
@Composable
fun SignInAgainCard(controller: MayiController, needed: AwsSignInNeededInfo) {
    val context = LocalContext.current
    var flow by remember(needed.runId) { mutableStateOf<AwsSignInFlow?>(null) }
    var begin by remember(needed.runId) { mutableStateOf(false) }
    var busy by remember(needed.runId) { mutableStateOf(false) }
    var error by remember(needed.runId) { mutableStateOf<String?>(null) }

    LaunchedEffect(begin) {
        if (!begin) return@LaunchedEffect
        busy = true
        error = null
        withContext(Dispatchers.IO) { controller.beginAwsSignIn(needed.startUrl, needed.region) }
            .onSuccess { started -> open(context, started.verificationUrl()); flow = started }
            .onFailure { error = MayiController.describe(it) }
        busy = false
        begin = false
    }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                AwsLogo()
                Text("Sign in to ${needed.name} again?", style = MaterialTheme.typography.titleMedium)
            }
            Text(
                "Your AWS session ended: AWS ends it after a set time. A command is waiting for it.",
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            CodeWell(needed.request.command, maxLines = 4)
            val started = flow
            if (started != null) {
                Waiting(started) { started.cancel() }
                LaunchedEffect(started) {
                    withContext(Dispatchers.IO) { controller.finishAwsSignIn(started) }
                        .onSuccess { session ->
                            val problem = withContext(Dispatchers.IO) { controller.renewAwsSignIn(needed.name, session) }
                            if (problem == null) controller.answerSignIn(needed.runId, true) else error = problem
                        }
                        .onFailure { val why = MayiController.describe(it); if (why != CANCELLED) error = why }
                    flow = null
                }
            } else {
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.weight(1f).width(0.dp))
                    TextButton(onClick = { controller.answerSignIn(needed.runId, false) }) { Text("Not now") }
                    Button(onClick = { begin = true }, enabled = !busy) { Text("Sign in with AWS") }
                }
            }
        }
    }
}
