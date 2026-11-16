package dev.mayi.android

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.PanTool
import androidx.compose.material.icons.outlined.Receipt
import androidx.compose.material3.Icon
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import dev.mayi.ffi.RequestInfo
import android.text.format.DateUtils
import androidx.compose.foundation.layout.Column
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.PhoneAndroid
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.TextButton
import dev.mayi.ffi.RotateNoteRecord
import java.text.DateFormat
import java.util.Date

// A stock Material 3 app: the system's type, shapes and components, with one
// colour scheme built from the logo's blue. See docs/design-language.md.

private val LightColors = lightColorScheme(
    primary = Color(0xFF1F4FD8),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFDCE2FF),
    onPrimaryContainer = Color(0xFF001552),
    secondary = Color(0xFF595E72),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFDDE1F9),
    onSecondaryContainer = Color(0xFF161B2C),
    background = Color(0xFFFAF9FD),
    onBackground = Color(0xFF1A1B20),
    surface = Color(0xFFFAF9FD),
    onSurface = Color(0xFF1A1B20),
    surfaceVariant = Color(0xFFE2E2EC),
    onSurfaceVariant = Color(0xFF45464F),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF4F3F7),
    surfaceContainer = Color(0xFFEEEDF2),
    surfaceContainerHigh = Color(0xFFE8E7EC),
    surfaceContainerHighest = Color(0xFFE3E2E6),
    outline = Color(0xFF757680),
    outlineVariant = Color(0xFFC5C6D0),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFB7C4FF),
    onPrimary = Color(0xFF002682),
    primaryContainer = Color(0xFF0038B6),
    onPrimaryContainer = Color(0xFFDCE2FF),
    secondary = Color(0xFFC1C5DD),
    onSecondary = Color(0xFF2B3042),
    secondaryContainer = Color(0xFF414659),
    onSecondaryContainer = Color(0xFFDDE1F9),
    background = Color(0xFF121317),
    onBackground = Color(0xFFE3E2E6),
    surface = Color(0xFF121317),
    onSurface = Color(0xFFE3E2E6),
    surfaceVariant = Color(0xFF45464F),
    onSurfaceVariant = Color(0xFFC5C6D0),
    surfaceContainerLowest = Color(0xFF0D0E12),
    surfaceContainerLow = Color(0xFF1A1B20),
    surfaceContainer = Color(0xFF1E1F24),
    surfaceContainerHigh = Color(0xFF292A2E),
    surfaceContainerHighest = Color(0xFF343539),
    outline = Color(0xFF8F909A),
    outlineVariant = Color(0xFF45464F),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
)

@Composable
fun MayiTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors, content = content)
}

/** The app icon, drawn small: the logo on its white plate. */
@Composable
fun AppIcon(size: Dp = 40.dp) {
    val plate = RoundedCornerShape(percent = 24)
    Box(
        Modifier
            .size(size)
            .background(Color.White, plate)
            .border(0.5.dp, Color.Black.copy(alpha = 0.12f), plate),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            painterResource(R.drawable.ic_mayi_glyph), contentDescription = null, tint = Color(0xFF1F4FD8),
            modifier = Modifier.size(size * 0.62f),
        )
    }
}

val levelNames = listOf("Log", "Notify", "Approve", "Biometric")

val levelDetails = listOf(
    "Released silently and recorded in Activity.",
    "Released at once. You are notified and can stop the command.",
    "Held until you approve the command.",
    "Locked to this phone’s fingerprint. Every unlock needs it.",
)

val loginLevelDetails = listOf(
    "Typed in without asking, and recorded in Activity.",
    "Typed in at once. You are notified and can stop the session.",
    "Typed in once you approve the sign-in.",
    "Locked to this phone’s fingerprint. Every sign-in needs it.",
)

fun levelIcon(level: Int): ImageVector = when (level) {
    1 -> Icons.Outlined.Receipt
    2 -> Icons.Outlined.Notifications
    3 -> Icons.Outlined.PanTool
    else -> Icons.Outlined.Fingerprint
}

/** A level as the system would show it: its icon and its name. */
@Composable
fun LevelLabel(level: Int, color: Color = MaterialTheme.colorScheme.onSurfaceVariant) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        modifier = Modifier.clearAndSetSemantics { contentDescription = "Level $level, ${levelNames[level - 1]}" },
    ) {
        Icon(levelIcon(level), contentDescription = null, tint = color, modifier = Modifier.size(18.dp))
        Text(levelNames[level - 1], style = MaterialTheme.typography.labelLarge, color = color)
    }
}

/** A command or a token: literal, selectable, monospaced. */
@Composable
fun CodeWell(text: String, maxLines: Int = Int.MAX_VALUE) {
    SelectionContainer {
        Text(
            text,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
            color = LocalContentColor.current,
            maxLines = maxLines,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surfaceContainerHighest, MaterialTheme.shapes.small)
                .padding(horizontal = 12.dp, vertical = 10.dp),
        )
    }
}

/** A code for another device's camera: black on white in either theme. */
@Composable
fun QrCode(text: String, size: Dp = 220.dp) {
    val bitmap = androidx.compose.runtime.remember(text) {
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.MARGIN to 1))
        val pixels = IntArray(matrix.width * matrix.height) { i ->
            if (matrix.get(i % matrix.width, i / matrix.width)) android.graphics.Color.BLACK else android.graphics.Color.WHITE
        }
        Bitmap.createBitmap(pixels, matrix.width, matrix.height, Bitmap.Config.ARGB_8888).asImageBitmap()
    }
    Box(
        Modifier.size(size).background(Color.White, RoundedCornerShape(12.dp)).padding(10.dp),
        contentAlignment = Alignment.Center,
    ) {
        Image(bitmap, contentDescription = "QR code", filterQuality = FilterQuality.None, modifier = Modifier.fillMaxWidth())
    }
}

fun copyText(context: Context, label: String, text: String) {
    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText(label, text))
}

/**
 * Copies a secret's value, marked so the system does not show it in its
 * clipboard preview, and clears it after a minute unless something else was
 * copied since.
 */
fun copySecret(context: Context, text: String) {
    val clipboard = context.getSystemService(ClipboardManager::class.java)
    val label = "Mayi value"
    val clip = ClipData.newPlainText(label, text)
    clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
    clipboard.setPrimaryClip(clip)
    Handler(Looper.getMainLooper()).postDelayed({
        // Unreadable when Mayi is in the background: cleared then too.
        val current = clipboard.primaryClipDescription?.label
        if (current == null || current == label) clipboard.clearPrimaryClip()
    }, 60_000)
}

/** Amber: a secret that exists only on this phone. */
val oneCopyColor = Color(0xFFF29900)

/** Marks a secret that exists only on this phone, so it is lost if the phone is. */
@Composable
fun OneCopyDot() {
    Box(
        Modifier.size(8.dp).background(oneCopyColor, CircleShape)
            .semantics { contentDescription = "Only on this phone" },
    )
}

fun shareText(context: Context, text: String) {
    val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
    context.startActivity(Intent.createChooser(send, null).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}

/** "build-vm (3f9a1c2e)" as the name and the key id. */
fun requesterParts(label: String): Pair<String, String?> {
    val open = label.lastIndexOf(" (")
    if (!label.endsWith(")") || open < 0) return label to null
    return label.substring(0, open) to label.substring(open + 2, label.length - 1)
}

/**
 * Where a request comes from: a paired machine stands out in amber with its
 * name and key id, so a request from an unexpected machine is noticed.
 */
@Composable
fun RequesterChip(request: RequestInfo, compact: Boolean = false) {
    val (name, key) = if (request.remote) requesterParts(request.requester) else "this phone" to null
    val scheme = MaterialTheme.colorScheme
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        modifier = Modifier
            .background(if (request.remote) oneCopyColor.copy(alpha = 0.18f) else scheme.surfaceContainerHighest, CircleShape)
            .padding(horizontal = if (compact) 8.dp else 10.dp, vertical = if (compact) 2.dp else 4.dp)
            .clearAndSetSemantics { contentDescription = "From $name" + (key?.let { ", key $it" } ?: "") },
    ) {
        Icon(
            if (request.remote) Icons.Outlined.Dns else Icons.Outlined.PhoneAndroid, contentDescription = null,
            tint = scheme.onSurface, modifier = Modifier.size(if (compact) 14.dp else 16.dp),
        )
        Text(
            "From $name", style = if (compact) MaterialTheme.typography.labelMedium else MaterialTheme.typography.titleSmall,
            color = scheme.onSurface, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false),
        )
        if (key != null && !compact) {
            Text(key, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace, color = scheme.onSurfaceVariant)
        }
    }
}

/** "today", "yesterday" or "on 3 Nov 2026", for a sentence. */
private fun noteWhen(atMs: Long): String = when {
    DateUtils.isToday(atMs) -> "today"
    DateUtils.isToday(atMs + DateUtils.DAY_IN_MILLIS) -> "yesterday"
    else -> "on " + DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(atMs))
}

/** "Mac mini, revoked today" for each note. */
fun rotationSummary(notes: List<RotateNoteRecord>): String =
    notes.joinToString("; ") { "${it.who}, ${it.why} ${noteWhen(it.atMs.toLong())}" }

/** What to do about a secret that may be known to a revoked machine or a removed device. */
fun rotationAdvice(notes: List<RotateNoteRecord>): String {
    val events = notes.map { "${it.who} was ${it.why} ${noteWhen(it.atMs.toLong())}" }
    val all = if (events.size == 1) events[0] + ", and may still have this value."
    else events.joinToString(". ") + ". They may still have this value."
    return "$all Replace it where it was issued, for example with a new token from the service, then save the " +
        "new value here: that clears this note."
}

/** Amber warning: a secret whose value may be known to a revoked machine or removed device. */
@Composable
fun RotationCard(notes: List<RotateNoteRecord>, onDismiss: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = oneCopyColor.copy(alpha = 0.14f)),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(Icons.Filled.Warning, contentDescription = null, tint = oneCopyColor, modifier = Modifier.size(20.dp))
                Text("Replace this value", style = MaterialTheme.typography.titleSmall)
            }
            Text(rotationAdvice(notes), style = MaterialTheme.typography.bodyMedium)
            TextButton(onClick = onDismiss, modifier = Modifier.align(Alignment.End)) { Text("Dismiss") }
        }
    }
}

/** The host of an origin such as `https://github.com`, with its port if it has one, for a sentence. */
fun host(site: String): String = site.substringAfter("://").substringBefore('/').ifEmpty { site }

/** The fields of a sign-in, as words: "the username, password and two-factor code". */
fun fieldWords(fields: List<String>): String {
    val words = fields.map { if (it == "totp") "two-factor code" else it }
    return when (words.size) {
        0 -> "nothing"
        1 -> "the ${words[0]}"
        else -> "the " + words.dropLast(1).joinToString() + " and " + words.last()
    }
}
