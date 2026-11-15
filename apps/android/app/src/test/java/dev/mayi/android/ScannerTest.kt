package dev.mayi.android

import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ScannerTest {
    /** A camera frame's brightness plane showing [text] as a QR code, rows padded as cameras do. */
    private fun frame(text: String, size: Int, rowStride: Int): ByteArray {
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size)
        val bytes = ByteArray(rowStride * size) { 0xC8.toByte() }
        for (y in 0 until size) for (x in 0 until size) {
            if (matrix[x, y]) bytes[y * rowStride + x] = 0x10
        }
        return bytes
    }

    @Test
    fun readsAJoinCodeFromAFrame() {
        val code = "mayij1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElK"
        assertEquals(code, decodeQr(frame(code, 640, 704), 704, 640, 640))
    }

    @Test
    fun aFrameWithoutACodeGivesNothing() {
        assertNull(decodeQr(ByteArray(704 * 480) { 0x80.toByte() }, 704, 640, 480))
    }
}
