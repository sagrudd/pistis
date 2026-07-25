package org.mnemosynebiosciences.pistis.model

/** Ingestion routes share one validation and approval ceremony. */
public enum class ChallengeRoute {
    QR,
    DIRECT_LOCAL,
}

/** Supported approval intent at the portable domain boundary. */
public enum class ApprovalPurpose {
    AUTHENTICATE,
    APPROVE_ACTION,
    SIGN_EVIDENCE,
}

/** A bounded, already-decoded challenge. Canonical protocol bytes remain outside this module. */
public data class ApprovalChallenge(
    public val id: DomainIdentifier,
    public val installationId: DomainIdentifier,
    public val identityId: DomainIdentifier,
    public val purpose: ApprovalPurpose,
    public val route: ChallengeRoute,
    public val expiresAtEpochSeconds: Long,
)

/** Independent human decision fact. */
public enum class HumanDecision {
    PENDING,
    APPROVED,
    DENIED,
}

/** Independent local-authentication fact. */
public sealed interface LocalAuthenticationFact {
    public data object NotAttempted : LocalAuthenticationFact
    public data class Verified(public val method: VerificationMethod) : LocalAuthenticationFact
    public data class Failed(public val reason: String) : LocalAuthenticationFact
}

/** System-reported user verification method, without conflating credentials with biometrics. */
public enum class VerificationMethod {
    BIOMETRIC,
    DEVICE_CREDENTIAL,
}

/** Independent device-signature fact. */
public sealed interface DeviceSignatureFact {
    public data object NotAttempted : DeviceSignatureFact
    public data class Created(public val fingerprint: Sha256Fingerprint) : DeviceSignatureFact
    public data class Failed(public val reason: String) : DeviceSignatureFact
}

/** Independent transfer fact. */
public enum class TransferFact {
    NOT_ATTEMPTED,
    PRESENTED,
    DELIVERED,
    FAILED,
}

/** Independent relying-server verification fact. */
public enum class ServerVerificationFact {
    NOT_OBSERVED,
    ACCEPTED,
    REJECTED,
}

/** Evidence facts are deliberately not collapsed into one success indicator. */
public data class ApprovalFacts(
    public val humanDecision: HumanDecision = HumanDecision.PENDING,
    public val localAuthentication: LocalAuthenticationFact = LocalAuthenticationFact.NotAttempted,
    public val deviceSignature: DeviceSignatureFact = DeviceSignatureFact.NotAttempted,
    public val transfer: TransferFact = TransferFact.NOT_ATTEMPTED,
    public val serverVerification: ServerVerificationFact = ServerVerificationFact.NOT_OBSERVED,
)
