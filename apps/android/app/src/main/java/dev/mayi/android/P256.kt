package dev.mayi.android

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

/**
 * P-256 in the encodings the Rust core uses: public keys as uncompressed
 * SEC1 points (65 bytes), ECDH results as the raw 32-byte shared secret.
 */
object P256 {
    private val curve: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC")
            .apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
    }

    private fun fixed(n: BigInteger): ByteArray {
        val bytes = n.toByteArray()
        // toByteArray may add a sign byte or drop leading zeros.
        return when {
            bytes.size == 32 -> bytes
            bytes.size > 32 -> bytes.copyOfRange(bytes.size - 32, bytes.size)
            else -> ByteArray(32 - bytes.size) + bytes
        }
    }

    fun encode(key: PublicKey): ByteArray {
        val point = (key as ECPublicKey).w
        return byteArrayOf(4) + fixed(point.affineX) + fixed(point.affineY)
    }

    fun decode(bytes: ByteArray): PublicKey {
        require(bytes.size == 65 && bytes[0] == 4.toByte()) { "not an uncompressed P-256 point" }
        val point = ECPoint(BigInteger(1, bytes.copyOfRange(1, 33)), BigInteger(1, bytes.copyOfRange(33, 65)))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, curve))
    }

    /** ECDH with [private], which may live in a hardware key store named by [provider]. */
    fun agree(private: PrivateKey, peer: ByteArray, provider: String? = null): ByteArray {
        val agreement =
            if (provider == null) KeyAgreement.getInstance("ECDH") else KeyAgreement.getInstance("ECDH", provider)
        agreement.init(private)
        agreement.doPhase(decode(peer), true)
        return agreement.generateSecret()
    }
}
