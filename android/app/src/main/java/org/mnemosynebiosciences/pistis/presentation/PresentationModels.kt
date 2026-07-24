package org.mnemosynebiosciences.pistis.presentation

enum class PistisDestination(val label: String, val shortLabel: String) {
    IDENTITIES("Identities", "I"),
    INSTALLATIONS("Installations", "N"),
    SCAN("Scan", "S"),
    HISTORY("History", "H"),
    SETTINGS("Settings", "G"),
}

data class IdentitySummary(
    val stableId: String,
    val provider: String,
    val displayName: String,
    val stableSubject: String,
    val status: EvidenceStatus,
)

data class InstallationSummary(
    val stableId: String,
    val name: String,
    val localAlias: String,
    val fingerprint: String,
    val trustStatus: EvidenceStatus,
    val lastUsed: String?,
)

data class ApprovalRequestPresentation(
    val action: String,
    val subject: String,
    val installation: String,
    val localUser: String,
    val externalIdentity: String,
    val fingerprint: String,
    val expiry: String,
    val route: String,
    val trustStatus: EvidenceStatus,
)

data class ApprovalResultFacts(
    val humanDecision: EvidenceStatus,
    val localAuthentication: EvidenceStatus,
    val deviceSignature: EvidenceStatus,
    val transfer: EvidenceStatus,
    val serverVerification: EvidenceStatus,
)

data class LocalHistorySummary(
    val stableId: String,
    val action: String,
    val installation: String,
    val observedAt: String,
    val facts: ApprovalResultFacts,
)

enum class StatusKind { SUCCESS, WARNING, DANGER, NEUTRAL }

data class EvidenceStatus(val words: String, val kind: StatusKind)

data class DeviceSecurityPresentation(
    val signingKey: EvidenceStatus,
    val authenticationPolicy: EvidenceStatus,
    val securityLevel: EvidenceStatus,
    val attestation: EvidenceStatus,
) {
    companion object {
        fun unavailable() = DeviceSecurityPresentation(
            signingKey = EvidenceStatus("Signing key: Not configured", StatusKind.WARNING),
            authenticationPolicy = EvidenceStatus(
                "Local verification: Not configured",
                StatusKind.WARNING,
            ),
            securityLevel = EvidenceStatus(
                "Hardware capability: Not observed",
                StatusKind.NEUTRAL,
            ),
            attestation = EvidenceStatus(
                "Remote attestation: Not requested",
                StatusKind.NEUTRAL,
            ),
        )
    }
}

data class PistisUiState(
    val hasCompletedOnboarding: Boolean,
    val identities: List<IdentitySummary>,
    val installations: List<InstallationSummary>,
    val history: List<LocalHistorySummary>,
    val deviceSecurity: DeviceSecurityPresentation,
) {
    companion object {
        fun empty() = PistisUiState(
            hasCompletedOnboarding = false,
            identities = emptyList(),
            installations = emptyList(),
            history = emptyList(),
            deviceSecurity = DeviceSecurityPresentation.unavailable(),
        )
    }
}
