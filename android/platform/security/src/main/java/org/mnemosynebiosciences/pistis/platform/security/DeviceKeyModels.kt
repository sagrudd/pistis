package org.mnemosynebiosciences.pistis.platform.security

/** Local Android Keystore security level. This is reported, not remotely attested. */
enum class ReportedSecurityLevel {
    STRONGBOX,
    TRUSTED_ENVIRONMENT,
    SOFTWARE,
    UNKNOWN_SECURE,
    UNKNOWN,
}

/** Permitted local authorization for one signing key. */
enum class AuthorizationPolicy {
    STRONG_BIOMETRIC,
    STRONG_BIOMETRIC_OR_DEVICE_CREDENTIAL,
}

/** Locally inspected properties of an Android Keystore signing key. */
data class ReportedKeyCapability(
    val securityLevel: ReportedSecurityLevel,
    val signingPurpose: Boolean,
    val sha256Digest: Boolean,
    val generatedInKeystore: Boolean,
    val userAuthenticationRequired: Boolean,
    val perOperationAuthentication: Boolean,
    val authorizationPolicy: AuthorizationPolicy?,
) {
    /** Hardware storage may be reported locally but is not verified attestation. */
    val reportsHardwareStorage: Boolean
        get() = securityLevel == ReportedSecurityLevel.STRONGBOX ||
            securityLevel == ReportedSecurityLevel.TRUSTED_ENVIRONMENT
}

/** Result of an explicit key-generation attempt. */
sealed interface KeyGenerationOutcome {
    data class Created(
        val alias: String,
        val compressedPublicKey: ByteArray,
        val capability: ReportedKeyCapability,
    ) : KeyGenerationOutcome {
        override fun equals(other: Any?): Boolean =
            other is Created &&
                alias == other.alias &&
                compressedPublicKey.contentEquals(other.compressedPublicKey) &&
                capability == other.capability

        override fun hashCode(): Int =
            31 * (31 * alias.hashCode() + compressedPublicKey.contentHashCode()) +
                capability.hashCode()
    }

    /** StrongBox was requested but unavailable. No fallback was attempted. */
    data object StrongBoxUnavailable : KeyGenerationOutcome

    data class Rejected(val reason: KeyFailure) : KeyGenerationOutcome
}

enum class KeyFailure {
    DEVICE_NOT_SECURE,
    KEY_ALREADY_EXISTS,
    KEY_MISSING,
    KEY_INVALIDATED,
    UNSUPPORTED_KEY,
    CAPABILITY_MISMATCH,
    KEYSTORE_FAILURE,
}

enum class SigningFailure {
    KEY_MISSING,
    KEY_INVALIDATED,
    AUTHENTICATION_UNAVAILABLE,
    AUTHENTICATION_CANCELLED,
    AUTHENTICATION_LOCKED_OUT,
    AUTHENTICATION_FAILED,
    BACKGROUNDED,
    CRYPTO_OBJECT_MISSING,
    CRYPTO_OBJECT_CHANGED,
    PAYLOAD_CHANGED,
    AUTHENTICATOR_MISMATCH,
    EXPIRED,
    SIGNATURE_FORMAT_INVALID,
    SIGNING_FAILED,
}

/** Local authorization mechanism actually reported by BiometricPrompt. */
enum class LocalAuthorization {
    BIOMETRIC,
    DEVICE_CREDENTIAL,
}

sealed interface SigningOutcome {
    data class Signed(
        val signature: ByteArray,
        val authorization: LocalAuthorization,
    ) : SigningOutcome {
        override fun equals(other: Any?): Boolean =
            other is Signed &&
                signature.contentEquals(other.signature) &&
                authorization == other.authorization

        override fun hashCode(): Int = 31 * signature.contentHashCode() + authorization.hashCode()
    }

    data class Rejected(val reason: SigningFailure) : SigningOutcome
}
