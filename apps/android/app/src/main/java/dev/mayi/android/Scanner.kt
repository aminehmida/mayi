package dev.mayi.android

import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The text of the QR code in a frame's brightness plane (`rowStride` bytes
 * a row), or null if there is none.
 */
internal fun decodeQr(luminance: ByteArray, rowStride: Int, width: Int, height: Int): String? {
    val reader = MultiFormatReader().apply {
        setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)))
    }
    val source = PlanarYUVLuminanceSource(luminance, rowStride, height, 0, 0, width, height, false)
    return try {
        reader.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text
    } catch (e: NotFoundException) {
        null
    }
}

/** Reads QR codes from camera frames, using only their brightness. */
private class QrReader(private val onCode: (String) -> Unit) : ImageAnalysis.Analyzer {
    override fun analyze(image: ImageProxy) {
        try {
            val plane = image.planes[0]
            val bytes = ByteArray(plane.buffer.remaining()).also { plane.buffer.get(it) }
            decodeQr(bytes, plane.rowStride, image.width, image.height)?.let(onCode)
        } finally {
            image.close()
        }
    }
}

/**
 * The camera, full screen, until it sees a QR code: then [onCode] is called
 * once. Needs the camera permission already granted.
 */
@Composable
fun QrScanner(owner: LifecycleOwner, onCode: (String) -> Unit, onCancel: () -> Unit) {
    val found = remember { AtomicBoolean(false) }
    val analysis = remember { Executors.newSingleThreadExecutor() }
    val release = remember { mutableListOf<() -> Unit>() }
    Box(Modifier.fillMaxSize().background(Color.Black)) {
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { context ->
                val view = PreviewView(context)
                val providerFuture = ProcessCameraProvider.getInstance(context)
                providerFuture.addListener({
                    val provider = providerFuture.get()
                    val preview = Preview.Builder().build().also { it.setSurfaceProvider(view.surfaceProvider) }
                    val frames = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()
                    frames.setAnalyzer(analysis, QrReader { code ->
                        if (found.compareAndSet(false, true)) view.post { onCode(code) }
                    })
                    provider.unbindAll()
                    provider.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, frames)
                    release += { provider.unbindAll() }
                }, ContextCompat.getMainExecutor(context))
                view
            },
        )
        Column(
            Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceBetween,
        ) {
            // Dark backings keep the controls readable over any picture.
            val backing = Color.Black.copy(alpha = 0.6f)
            Box(Modifier.align(Alignment.End).background(backing, CircleShape)) {
                IconButton(onClick = onCancel) {
                    Icon(Icons.Outlined.Close, contentDescription = "Cancel", tint = Color.White)
                }
            }
            Box(Modifier.size(240.dp).border(2.dp, Color.White, RoundedCornerShape(16.dp)))
            Text(
                "Point the camera at the code on your other device.",
                style = MaterialTheme.typography.bodyLarge, color = Color.White, textAlign = TextAlign.Center,
                modifier = Modifier.background(backing, RoundedCornerShape(12.dp)).padding(horizontal = 16.dp, vertical = 10.dp),
            )
        }
    }
    DisposableEffect(Unit) {
        onDispose {
            release.forEach { it() }
            analysis.shutdown()
        }
    }
}
