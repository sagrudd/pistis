package org.mnemosynebiosciences.pistis.platform.security

import android.app.KeyguardManager
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Narrow Android Keystore boundary for Pistis device signing keys.
 *
 * StrongBox and non-StrongBox generation are separate entry points so an
 * unavailable StrongBox can never cause an implicit assurance downgrade.
 */
class AndroidDeviceKeyStore(
    context: Context,
    private val keyStore: KeyStore = androidKeyStore(),
) {
    private val keyguardManager = context.getSystemService(KeyguardManager::class.java)

    fun generateStrongBox(
        alias: String,
        authorizationPolicy: AuthorizationPolicy,
    ): KeyGenerationOutcome = generate(alias, authorizationPolicy, strongBox = true)

    /**
     * Explicitly attempts the platform-default Keystore security level.
     *
     * Callers may invoke this only after policy accepts a non-StrongBox result.
     * The returned capability still reports TEE, software, or unknown exactly.
     */
    fun generatePlatformDefault(
        alias: String,
        authorizationPolicy: AuthorizationPolicy,
    ): KeyGenerationOutcome = generate(alias, authorizationPolicy, strongBox = false)

    fun reportedCapability(alias: String): Result<ReportedKeyCapability> = runCatching {
        val privateKey = keyStore.getKey(alias, null)
            ?: throw DeviceKeyException(KeyFailure.KEY_MISSING)
        val keyInfo = KeyFactory
            .getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(privateKey, KeyInfo::class.java)
        capability(keyInfo)
    }

    fun compressedPublicKey(alias: String): Result<ByteArray> = runCatching {
        val publicKey = keyStore.getCertificate(alias)?.publicKey as? ECPublicKey
            ?: throw DeviceKeyException(KeyFailure.KEY_MISSING)
        P256PublicKey.compressed(publicKey)
    }

    internal fun privateKey(alias: String) = try {
        keyStore.getKey(alias, null) as? java.security.PrivateKey
            ?: throw DeviceKeyException(KeyFailure.KEY_MISSING)
    } catch (error: KeyPermanentlyInvalidatedException) {
        throw DeviceKeyException(KeyFailure.KEY_INVALIDATED, error)
    } catch (error: UnrecoverableKeyException) {
        throw DeviceKeyException(KeyFailure.KEY_INVALIDATED, error)
    }

    private fun generate(
        alias: String,
        authorizationPolicy: AuthorizationPolicy,
        strongBox: Boolean,
    ): KeyGenerationOutcome {
        if (!keyguardManager.isDeviceSecure) {
            return KeyGenerationOutcome.Rejected(KeyFailure.DEVICE_NOT_SECURE)
        }
        if (keyStore.containsAlias(alias)) {
            return KeyGenerationOutcome.Rejected(KeyFailure.KEY_ALREADY_EXISTS)
        }

        return try {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE,
            )
            val specification = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec(P256_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, authorizationPolicy.keyPropertiesFlags())
                .setIsStrongBoxBacked(strongBox)
                .build()
            generator.initialize(specification)
            val pair = generator.generateKeyPair()
            val keyInfo = KeyFactory
                .getInstance(pair.private.algorithm, ANDROID_KEYSTORE)
                .getKeySpec(pair.private, KeyInfo::class.java)
            val reported = capability(keyInfo)
            if (!reported.matches(authorizationPolicy)) {
                keyStore.deleteEntry(alias)
                KeyGenerationOutcome.Rejected(KeyFailure.CAPABILITY_MISMATCH)
            } else {
                KeyGenerationOutcome.Created(
                    alias = alias,
                    compressedPublicKey = P256PublicKey.compressed(pair.public as ECPublicKey),
                    capability = reported,
                )
            }
        } catch (_: StrongBoxUnavailableException) {
            KeyGenerationOutcome.StrongBoxUnavailable
        } catch (_: InvalidAlgorithmParameterException) {
            deleteFailedGeneration(alias)
            KeyGenerationOutcome.Rejected(KeyFailure.UNSUPPORTED_KEY)
        } catch (_: Exception) {
            deleteFailedGeneration(alias)
            KeyGenerationOutcome.Rejected(KeyFailure.KEYSTORE_FAILURE)
        }
    }

    private fun deleteFailedGeneration(alias: String) {
        runCatching {
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        }
    }

    private fun capability(keyInfo: KeyInfo): ReportedKeyCapability {
        val authPolicy = when (keyInfo.userAuthenticationType) {
            KeyProperties.AUTH_BIOMETRIC_STRONG -> AuthorizationPolicy.STRONG_BIOMETRIC
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL ->
                AuthorizationPolicy.STRONG_BIOMETRIC_OR_DEVICE_CREDENTIAL
            else -> null
        }
        return ReportedKeyCapability(
            securityLevel = keyInfo.securityLevel.toReportedLevel(),
            signingPurpose = keyInfo.purposes and KeyProperties.PURPOSE_SIGN != 0,
            sha256Digest = keyInfo.digests.contains(KeyProperties.DIGEST_SHA256),
            generatedInKeystore = keyInfo.origin == KeyProperties.ORIGIN_GENERATED,
            userAuthenticationRequired = keyInfo.isUserAuthenticationRequired,
            perOperationAuthentication =
                keyInfo.userAuthenticationValidityDurationSeconds == -1,
            authorizationPolicy = authPolicy,
        )
    }

    private fun ReportedKeyCapability.matches(policy: AuthorizationPolicy): Boolean =
        signingPurpose &&
            sha256Digest &&
            generatedInKeystore &&
            userAuthenticationRequired &&
            perOperationAuthentication &&
            authorizationPolicy == policy

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val P256_CURVE = "secp256r1"

        private fun androidKeyStore(): KeyStore =
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }
}

class DeviceKeyException(
    val failure: KeyFailure,
    cause: Throwable? = null,
) : Exception(failure.name, cause)

internal fun AuthorizationPolicy.keyPropertiesFlags(): Int = when (this) {
    AuthorizationPolicy.STRONG_BIOMETRIC -> KeyProperties.AUTH_BIOMETRIC_STRONG
    AuthorizationPolicy.STRONG_BIOMETRIC_OR_DEVICE_CREDENTIAL ->
        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
}

internal fun Int.toReportedLevel(): ReportedSecurityLevel = when (this) {
    KeyProperties.SECURITY_LEVEL_STRONGBOX -> ReportedSecurityLevel.STRONGBOX
    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
        ReportedSecurityLevel.TRUSTED_ENVIRONMENT
    KeyProperties.SECURITY_LEVEL_SOFTWARE -> ReportedSecurityLevel.SOFTWARE
    KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> ReportedSecurityLevel.UNKNOWN_SECURE
    else -> ReportedSecurityLevel.UNKNOWN
}
