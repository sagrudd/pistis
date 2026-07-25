package org.mnemosynebiosciences.pistis.presentation

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PresentationModelsTest {
    @Test
    fun productionEmptyStateContainsNoDemonstrationEvidence() {
        val state = PistisUiState.empty()

        assertTrue(state.identities.isEmpty())
        assertTrue(state.installations.isEmpty())
        assertTrue(state.history.isEmpty())
        assertEquals("Signing key: Not configured", state.deviceSecurity.signingKey.words)
        assertEquals(
            "Hardware capability: Not observed",
            state.deviceSecurity.securityLevel.words,
        )
        assertEquals(
            "Remote attestation: Not requested",
            state.deviceSecurity.attestation.words,
        )
    }

    @Test
    fun resultFactsRemainIndependentValues() {
        val result = ApprovalResultFacts(
            humanDecision = EvidenceStatus("Human decision: Approved", StatusKind.SUCCESS),
            localAuthentication = EvidenceStatus(
                "Local authentication: Verified",
                StatusKind.SUCCESS,
            ),
            deviceSignature = EvidenceStatus("Device signature: Not produced", StatusKind.DANGER),
            transfer = EvidenceStatus("Transfer: Not attempted", StatusKind.NEUTRAL),
            serverVerification = EvidenceStatus(
                "Server verification: Not applicable",
                StatusKind.NEUTRAL,
            ),
        )

        assertEquals(StatusKind.SUCCESS, result.humanDecision.kind)
        assertEquals(StatusKind.DANGER, result.deviceSignature.kind)
        assertEquals(StatusKind.NEUTRAL, result.serverVerification.kind)
    }

    @Test
    fun fiveDestinationsMatchCrossPlatformContract() {
        assertEquals(
            listOf("Identities", "Installations", "Scan", "History", "Settings"),
            PistisDestination.entries.map(PistisDestination::label),
        )
    }
}
