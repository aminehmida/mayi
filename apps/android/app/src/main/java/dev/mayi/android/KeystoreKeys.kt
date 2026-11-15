package dev.mayi.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import dev.mayi.ffi.KeyException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec

/**
 * The device's two keys, generated in the Android Keystore. The private keys
 * never leave secure hardware.
 *
 * The biometric key can only be used for a few seconds after a strong
 * biometric check, and is invalidated if the enrolled fingerprints change.
 * [authenticate] must show that check and return whether it succeeded.
 */
class KeystoreKeys(
    /** Accept keys the system holds in software. Only ever true in a debug build on an emulator. */
    private val allowSoftwareKeys: Boolean = false,
    private val authenticate: (reason: String) -> Boolean,
) : dev.mayi.ffi.KeyStore {
    private val store = KeyStore.getInstance(PROVIDER).apply { load(null) }

    init {
        if (!store.containsAlias(DEVICE)) generate(DEVICE, biometric = false)
        if (!store.containsAlias(BIOMETRIC)) generate(BIOMETRIC, biometric = true)
    }

    private fun generate(alias: String, biometric: Boolean) {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setIsStrongBoxBacked(strongBox)
            .apply {
                if (biometric) {
                    setUserAuthenticationRequired(true)
                    setUserAuthenticationParameters(AUTH_WINDOW_SECS, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    setInvalidatedByBiometricEnrollment(true)
                }
            }
            .build()
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        try {
            generator.initialize(spec(strongBox = true))
            generator.generateKeyPair()
        } catch (e: StrongBoxUnavailableException) {
            generator.initialize(spec(strongBox = false))
            generator.generateKeyPair()
        }
        // A key held only in software would make level 4 meaningless.
        val info = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
            .getKeySpec(private(alias), KeyInfo::class.java)
        val hardware = info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
            info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        if (!hardware && !allowSoftwareKeys) {
            store.deleteEntry(alias)
            throw IllegalStateException("This device cannot keep keys in secure hardware.")
        }
    }

    private fun private(alias: String) = store.getKey(alias, null) as PrivateKey

    override fun devicePublic(): ByteArray = P256.encode(store.getCertificate(DEVICE).publicKey)

    override fun biometricPublic(): ByteArray = P256.encode(store.getCertificate(BIOMETRIC).publicKey)

    override fun deviceEcdh(peerPublic: ByteArray): ByteArray = try {
        P256.agree(private(DEVICE), peerPublic, PROVIDER)
    } catch (e: Exception) {
        throw KeyException.Failed("Keystore: ${e.message}")
    }

    override fun biometricEcdh(peerPublics: List<ByteArray>, prompt: String): List<ByteArray> {
        if (!authenticate(prompt)) throw KeyException.Denied()
        return try {
            // One check opens the key for a few seconds: enough for the batch.
            peerPublics.map { P256.agree(private(BIOMETRIC), it, PROVIDER) }
        } catch (e: UserNotAuthenticatedException) {
            throw KeyException.Denied()
        } catch (e: Exception) {
            throw KeyException.Failed("Keystore: ${e.message}")
        }
    }

    companion object {
        private const val PROVIDER = "AndroidKeyStore"
        private const val DEVICE = "mayi.device"
        private const val BIOMETRIC = "mayi.biometric"
        private const val AUTH_WINDOW_SECS = 10
    }
}
