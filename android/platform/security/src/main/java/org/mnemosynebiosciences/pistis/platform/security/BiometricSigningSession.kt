package org.mnemosynebiosciences.pistis.platform.security

import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricManager
import androidx.fragment.app.FragmentActivity
import android.security.keystore.KeyPermanentlyInvalidatedException
import java.security.MessageDigest
import java.security.Signature
import java.util.concurrent.Executor

/**
 * One-use, CryptoObject-bound authorization and signing session.
 *
 * A session owns a fresh initialized Signature and immutable payload snapshot.
 * It cannot be reused after success, failure, cancellation, or backgrounding.
 */
class BiometricSigningSession private constructor(
    private val activity: FragmentActivity,
    private val executor: Executor,
    private val prepared: PreparedSigning,
    private val promptInfo: BiometricPrompt.PromptInfo,
) {
    private val gate = OneUseOperationGate()
    private val promptLock = Any()
    private var prompt: BiometricPrompt? = null

    fun authenticate(callback: (SigningOutcome) -> Unit) {
        synchronized(promptLock) {
            if (!gate.start()) {
                callback(SigningOutcome.Rejected(SigningFailure.AUTHENTICATION_FAILED))
                return
            }
            prompt = BiometricPrompt(
                activity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult,
                    ) {
                        finishSuccessfully(result, callback)
                    }

                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence,
                    ) {
                        finishWithoutSigning(
                            SigningOutcome.Rejected(errorCode.toSigningFailure()),
                            callback,
                        )
                    }

                    override fun onAuthenticationFailed() {
                        // The prompt remains active. No key operation occurs.
                    }
                },
            )
            prompt?.authenticate(promptInfo, prepared.cryptoObject)
        }
    }

    /** Cancels the operation when the host leaves the foreground. */
    fun onBackgrounded(callback: (SigningOutcome) -> Unit) {
        cancel(SigningFailure.BACKGROUNDED, callback)
    }

    fun cancel(callback: (SigningOutcome) -> Unit) {
        cancel(SigningFailure.AUTHENTICATION_CANCELLED, callback)
    }

    private fun cancel(failure: SigningFailure, callback: (SigningOutcome) -> Unit) {
        synchronized(promptLock) {
            if (!gate.cancel()) return
            prompt?.cancelAuthentication()
            prepared.invalidate()
            prompt = null
        }
        callback(SigningOutcome.Rejected(failure))
    }

    private fun finishSuccessfully(
        result: BiometricPrompt.AuthenticationResult,
        callback: (SigningOutcome) -> Unit,
    ) {
        if (!gate.finish()) return
        val outcome = prepared.finish(result)
        prepared.invalidate()
        synchronized(promptLock) { prompt = null }
        callback(outcome)
    }

    private fun finishWithoutSigning(
        outcome: SigningOutcome,
        callback: (SigningOutcome) -> Unit,
    ) {
        if (!gate.finish()) return
        prepared.invalidate()
        synchronized(promptLock) { prompt = null }
        callback(outcome)
    }

    companion object {
        fun create(
            activity: FragmentActivity,
            executor: Executor,
            keyStore: AndroidDeviceKeyStore,
            alias: String,
            canonicalPayload: ByteArray,
            authorizationPolicy: AuthorizationPolicy,
            expiresAtEpochSeconds: Long,
            title: String,
            subtitle: String,
            clock: EpochSecondsClock = EpochSecondsClock {
                System.currentTimeMillis() / 1_000
            },
        ): Result<BiometricSigningSession> = runCatching {
            require(canonicalPayload.isNotEmpty()) { "canonical payload is empty" }
            val deadline = SigningDeadline(expiresAtEpochSeconds)
            if (deadline.isExpired(clock.now())) {
                throw SigningPreparationException(SigningFailure.EXPIRED)
            }
            val authenticatorFlags = authorizationPolicy.biometricFlags()
            if (BiometricManager.from(activity).canAuthenticate(authenticatorFlags) !=
                BiometricManager.BIOMETRIC_SUCCESS
            ) {
                throw SigningPreparationException(SigningFailure.AUTHENTICATION_UNAVAILABLE)
            }
            val signature = Signature.getInstance("SHA256withECDSA")
            try {
                signature.initSign(keyStore.privateKey(alias))
            } catch (error: DeviceKeyException) {
                val failure = when (error.failure) {
                    KeyFailure.KEY_MISSING -> SigningFailure.KEY_MISSING
                    KeyFailure.KEY_INVALIDATED -> SigningFailure.KEY_INVALIDATED
                    else -> SigningFailure.SIGNING_FAILED
                }
                throw SigningPreparationException(failure, error)
            } catch (error: KeyPermanentlyInvalidatedException) {
                throw SigningPreparationException(SigningFailure.KEY_INVALIDATED, error)
            }
            val prepared = PreparedSigning(
                signature,
                canonicalPayload,
                authorizationPolicy,
                deadline,
                clock,
            )
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setConfirmationRequired(true)
                .setAllowedAuthenticators(authenticatorFlags)
                .build()
            BiometricSigningSession(activity, executor, prepared, promptInfo)
        }
    }
}

internal class PreparedSigning(
    private var signature: Signature?,
    canonicalPayload: ByteArray,
    private val authorizationPolicy: AuthorizationPolicy,
    private val deadline: SigningDeadline,
    private val clock: EpochSecondsClock,
) {
    private var payload: ByteArray? = canonicalPayload.copyOf()
    val cryptoObject = BiometricPrompt.CryptoObject(requireNotNull(signature))

    fun finish(result: BiometricPrompt.AuthenticationResult): SigningOutcome {
        if (deadline.isExpired(clock.now())) {
            return SigningOutcome.Rejected(SigningFailure.EXPIRED)
        }
        val expectedSignature = signature
            ?: return SigningOutcome.Rejected(SigningFailure.AUTHENTICATION_FAILED)
        val expectedPayload = payload
            ?: return SigningOutcome.Rejected(SigningFailure.PAYLOAD_CHANGED)
        val returnedSignature = result.cryptoObject?.signature
            ?: return SigningOutcome.Rejected(SigningFailure.CRYPTO_OBJECT_MISSING)
        if (returnedSignature !== expectedSignature) {
            return SigningOutcome.Rejected(SigningFailure.CRYPTO_OBJECT_CHANGED)
        }
        val authorization = result.authenticationType.toLocalAuthorization()
            ?: return SigningOutcome.Rejected(SigningFailure.AUTHENTICATOR_MISMATCH)
        if (!authorizationPolicy.permits(authorization)) {
            return SigningOutcome.Rejected(SigningFailure.AUTHENTICATOR_MISMATCH)
        }
        return try {
            returnedSignature.update(expectedPayload)
            SigningOutcome.Signed(DerEs256.toFixedLowS(returnedSignature.sign()), authorization)
        } catch (_: IllegalArgumentException) {
            SigningOutcome.Rejected(SigningFailure.SIGNATURE_FORMAT_INVALID)
        } catch (_: Exception) {
            SigningOutcome.Rejected(SigningFailure.SIGNING_FAILED)
        }
    }

    fun payloadMatches(candidate: ByteArray): Boolean =
        payload?.let { MessageDigest.isEqual(it, candidate) } == true

    fun invalidate() {
        payload?.fill(0)
        payload = null
        signature = null
    }
}

class SigningPreparationException(
    val failure: SigningFailure,
    cause: Throwable? = null,
) : Exception(failure.name, cause)

internal fun AuthorizationPolicy.biometricFlags(): Int = when (this) {
    AuthorizationPolicy.STRONG_BIOMETRIC ->
        androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
    AuthorizationPolicy.STRONG_BIOMETRIC_OR_DEVICE_CREDENTIAL ->
        androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
            androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
}

private fun AuthorizationPolicy.permits(authorization: LocalAuthorization): Boolean = when (this) {
    AuthorizationPolicy.STRONG_BIOMETRIC -> authorization == LocalAuthorization.BIOMETRIC
    AuthorizationPolicy.STRONG_BIOMETRIC_OR_DEVICE_CREDENTIAL -> true
}

private fun Int.toLocalAuthorization(): LocalAuthorization? = when (this) {
    BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC -> LocalAuthorization.BIOMETRIC
    BiometricPrompt.AUTHENTICATION_RESULT_TYPE_DEVICE_CREDENTIAL ->
        LocalAuthorization.DEVICE_CREDENTIAL
    else -> null
}

private fun Int.toSigningFailure(): SigningFailure = when (this) {
    BiometricPrompt.ERROR_CANCELED,
    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
    BiometricPrompt.ERROR_USER_CANCELED,
    -> SigningFailure.AUTHENTICATION_CANCELLED
    BiometricPrompt.ERROR_LOCKOUT,
    BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
    -> SigningFailure.AUTHENTICATION_LOCKED_OUT
    BiometricPrompt.ERROR_HW_NOT_PRESENT,
    BiometricPrompt.ERROR_HW_UNAVAILABLE,
    BiometricPrompt.ERROR_NO_BIOMETRICS,
    BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
    -> SigningFailure.AUTHENTICATION_UNAVAILABLE
    else -> SigningFailure.AUTHENTICATION_FAILED
}
