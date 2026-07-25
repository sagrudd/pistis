package org.mnemosynebiosciences.pistis.ceremony

import org.mnemosynebiosciences.pistis.model.ApprovalChallenge
import org.mnemosynebiosciences.pistis.model.ApprovalPurpose
import org.mnemosynebiosciences.pistis.model.ChallengeRoute
import org.mnemosynebiosciences.pistis.model.DeviceSignatureFact
import org.mnemosynebiosciences.pistis.model.DomainIdentifier
import org.mnemosynebiosciences.pistis.model.HumanDecision
import org.mnemosynebiosciences.pistis.model.Installation
import org.mnemosynebiosciences.pistis.model.InstallationTrustState
import org.mnemosynebiosciences.pistis.model.LocalAuthenticationFact
import org.mnemosynebiosciences.pistis.model.ServerVerificationFact
import org.mnemosynebiosciences.pistis.model.Sha256Fingerprint
import org.mnemosynebiosciences.pistis.model.TransferFact
import org.mnemosynebiosciences.pistis.model.VerificationMethod
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class ApprovalReducerTest {
    private val installationId = DomainIdentifier.parse("installation:01")
    private val identityId = DomainIdentifier.parse("identity:01")
    private val fingerprint = Sha256Fingerprint.parse("ab".repeat(32))
    private val installation = Installation(
        installationId,
        "Research workstation",
        fingerprint,
        InstallationTrustState.TRUSTED,
    )

    @Test
    fun `qr and direct local use the same reducer`() {
        ChallengeRoute.entries.forEach { route ->
            var state: ApprovalState = ApprovalState.Idle
            state = ApprovalReducer.reduce(state, ApprovalEvent.Begin(challenge(route), installation, 100))
            state = ApprovalReducer.reduce(state, ApprovalEvent.Approve(101))
            state = ApprovalReducer.reduce(
                state,
                ApprovalEvent.AuthenticationSucceeded(VerificationMethod.BIOMETRIC, 102),
            )
            state = ApprovalReducer.reduce(state, ApprovalEvent.SignatureCreated(fingerprint, 103))
            state = ApprovalReducer.reduce(state, ApprovalEvent.ResponsePresented)
            state = ApprovalReducer.reduce(state, ApprovalEvent.TransferDelivered)
            state = ApprovalReducer.reduce(
                state,
                ApprovalEvent.ServerResult(ServerVerificationFact.ACCEPTED),
            )

            val finished = assertIs<ApprovalState.Finished>(state)
            assertEquals(HumanDecision.APPROVED, finished.facts.humanDecision)
            assertEquals(
                LocalAuthenticationFact.Verified(VerificationMethod.BIOMETRIC),
                finished.facts.localAuthentication,
            )
            assertEquals(DeviceSignatureFact.Created(fingerprint), finished.facts.deviceSignature)
            assertEquals(TransferFact.DELIVERED, finished.facts.transfer)
            assertEquals(ServerVerificationFact.ACCEPTED, finished.facts.serverVerification)
        }
    }

    @Test
    fun `expired and changed installations fail before review`() {
        val expired = ApprovalReducer.reduce(
            ApprovalState.Idle,
            ApprovalEvent.Begin(challenge(ChallengeRoute.QR), installation, 200),
        )
        assertEquals(
            FailureReason.EXPIRED,
            assertIs<ApprovalState.Failed>(expired).reason,
        )

        val changed = installation.copy(trustState = InstallationTrustState.CHANGED)
        val untrusted = ApprovalReducer.reduce(
            ApprovalState.Idle,
            ApprovalEvent.Begin(challenge(ChallengeRoute.QR), changed, 100),
        )
        assertEquals(
            FailureReason.UNTRUSTED_INSTALLATION,
            assertIs<ApprovalState.Failed>(untrusted).reason,
        )
    }

    @Test
    fun `cancellation cannot create authentication or signature facts`() {
        var state: ApprovalState = ApprovalReducer.reduce(
            ApprovalState.Idle,
            ApprovalEvent.Begin(challenge(ChallengeRoute.QR), installation, 100),
        )
        state = ApprovalReducer.reduce(state, ApprovalEvent.Approve(101))
        state = ApprovalReducer.reduce(state, ApprovalEvent.Cancel)

        val failed = assertIs<ApprovalState.Failed>(state)
        assertEquals(FailureReason.CANCELLED, failed.reason)
        assertEquals(LocalAuthenticationFact.NotAttempted, failed.facts.localAuthentication)
        assertEquals(DeviceSignatureFact.NotAttempted, failed.facts.deviceSignature)
    }

    @Test
    fun `signature before authentication fails closed`() {
        val reviewing = ApprovalReducer.reduce(
            ApprovalState.Idle,
            ApprovalEvent.Begin(challenge(ChallengeRoute.DIRECT_LOCAL), installation, 100),
        )
        val failed = ApprovalReducer.reduce(
            reviewing,
            ApprovalEvent.SignatureCreated(fingerprint, 101),
        )
        assertEquals(
            FailureReason.INVALID_TRANSITION,
            assertIs<ApprovalState.Failed>(failed).reason,
        )
    }

    @Test
    fun `expiry during review fails before authentication`() {
        var state: ApprovalState = ApprovalReducer.reduce(
            ApprovalState.Idle,
            ApprovalEvent.Begin(challenge(ChallengeRoute.QR), installation, 100),
        )

        state = ApprovalReducer.reduce(state, ApprovalEvent.Approve(200))

        assertEquals(FailureReason.EXPIRED, assertIs<ApprovalState.Failed>(state).reason)
    }

    @Test
    fun `expiry after approval fails before signature state`() {
        var state: ApprovalState = ApprovalReducer.reduce(
            ApprovalState.Idle,
            ApprovalEvent.Begin(challenge(ChallengeRoute.QR), installation, 100),
        )
        state = ApprovalReducer.reduce(state, ApprovalEvent.Approve(199))

        state = ApprovalReducer.reduce(
            state,
            ApprovalEvent.AuthenticationSucceeded(VerificationMethod.BIOMETRIC, 200),
        )

        assertEquals(FailureReason.EXPIRED, assertIs<ApprovalState.Failed>(state).reason)
    }

    @Test
    fun `expiry at signature boundary rejects signature fact`() {
        var state: ApprovalState = ApprovalReducer.reduce(
            ApprovalState.Idle,
            ApprovalEvent.Begin(challenge(ChallengeRoute.QR), installation, 100),
        )
        state = ApprovalReducer.reduce(state, ApprovalEvent.Approve(198))
        state = ApprovalReducer.reduce(
            state,
            ApprovalEvent.AuthenticationSucceeded(VerificationMethod.BIOMETRIC, 199),
        )

        state = ApprovalReducer.reduce(state, ApprovalEvent.SignatureCreated(fingerprint, 200))

        val failed = assertIs<ApprovalState.Failed>(state)
        assertEquals(FailureReason.EXPIRED, failed.reason)
        assertEquals(DeviceSignatureFact.NotAttempted, failed.facts.deviceSignature)
    }

    private fun challenge(route: ChallengeRoute) = ApprovalChallenge(
        id = DomainIdentifier.parse("challenge:01"),
        installationId = installationId,
        identityId = identityId,
        purpose = ApprovalPurpose.APPROVE_ACTION,
        route = route,
        expiresAtEpochSeconds = 200,
    )
}
