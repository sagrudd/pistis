package org.mnemosynebiosciences.pistis.ceremony

import org.mnemosynebiosciences.pistis.model.ApprovalChallenge
import org.mnemosynebiosciences.pistis.model.ApprovalFacts
import org.mnemosynebiosciences.pistis.model.DeviceSignatureFact
import org.mnemosynebiosciences.pistis.model.HumanDecision
import org.mnemosynebiosciences.pistis.model.Installation
import org.mnemosynebiosciences.pistis.model.InstallationTrustState
import org.mnemosynebiosciences.pistis.model.LocalAuthenticationFact
import org.mnemosynebiosciences.pistis.model.ServerVerificationFact
import org.mnemosynebiosciences.pistis.model.Sha256Fingerprint
import org.mnemosynebiosciences.pistis.model.TransferFact
import org.mnemosynebiosciences.pistis.model.VerificationMethod

/** Deterministic approval state independent of Android lifecycle and cryptography. */
public sealed interface ApprovalState {
    public data object Idle : ApprovalState
    public data class Reviewing(
        public val challenge: ApprovalChallenge,
        public val facts: ApprovalFacts,
    ) : ApprovalState
    public data class AwaitingAuthentication(
        public val challenge: ApprovalChallenge,
        public val facts: ApprovalFacts,
    ) : ApprovalState
    public data class AwaitingSignature(
        public val challenge: ApprovalChallenge,
        public val facts: ApprovalFacts,
    ) : ApprovalState
    public data class AwaitingTransfer(
        public val challenge: ApprovalChallenge,
        public val facts: ApprovalFacts,
    ) : ApprovalState
    public data class Finished(public val facts: ApprovalFacts) : ApprovalState
    public data class Failed(public val reason: FailureReason, public val facts: ApprovalFacts) :
        ApprovalState
}

/** Closed failure reasons used by UI and evidence without leaking platform errors. */
public enum class FailureReason {
    EXPIRED,
    UNTRUSTED_INSTALLATION,
    CANCELLED,
    AUTHENTICATION_FAILED,
    SIGNATURE_FAILED,
    TRANSFER_FAILED,
    INVALID_TRANSITION,
}

/** Events produced by reviewed platform adapters. */
public sealed interface ApprovalEvent {
    public data class Begin(
        public val challenge: ApprovalChallenge,
        public val installation: Installation,
        public val nowEpochSeconds: Long,
    ) : ApprovalEvent
    public data class Approve(public val nowEpochSeconds: Long) : ApprovalEvent
    public data object Deny : ApprovalEvent
    public data class AuthenticationSucceeded(
        public val method: VerificationMethod,
        public val nowEpochSeconds: Long,
    ) : ApprovalEvent
    public data object AuthenticationFailed : ApprovalEvent
    public data class SignatureCreated(
        public val fingerprint: Sha256Fingerprint,
        public val nowEpochSeconds: Long,
    ) : ApprovalEvent
    public data object SignatureFailed : ApprovalEvent
    public data object ResponsePresented : ApprovalEvent
    public data object TransferDelivered : ApprovalEvent
    public data object TransferFailed : ApprovalEvent
    public data class ServerResult(public val result: ServerVerificationFact) : ApprovalEvent
    public data object Cancel : ApprovalEvent
}

/** Pure reducer shared by QR and direct-local ingestion routes. */
public object ApprovalReducer {
    /** Returns a new state and never resumes or signs implicitly. */
    public fun reduce(state: ApprovalState, event: ApprovalEvent): ApprovalState = when (event) {
        is ApprovalEvent.Begin -> begin(event)
        is ApprovalEvent.Approve -> when (state) {
            is ApprovalState.Reviewing -> ifExpired(state, event.nowEpochSeconds) {
                ApprovalState.AwaitingAuthentication(
                    state.challenge,
                    state.facts.copy(humanDecision = HumanDecision.APPROVED),
                )
            }
            else -> invalid(state)
        }
        ApprovalEvent.Deny -> when (state) {
            is ApprovalState.Reviewing -> ApprovalState.Finished(
                state.facts.copy(humanDecision = HumanDecision.DENIED),
            )
            else -> invalid(state)
        }
        is ApprovalEvent.AuthenticationSucceeded -> when (state) {
            is ApprovalState.AwaitingAuthentication -> ifExpired(state, event.nowEpochSeconds) {
                ApprovalState.AwaitingSignature(
                    state.challenge,
                    state.facts.copy(
                        localAuthentication = LocalAuthenticationFact.Verified(event.method),
                    ),
                )
            }
            else -> invalid(state)
        }
        ApprovalEvent.AuthenticationFailed -> failAuthentication(state)
        is ApprovalEvent.SignatureCreated -> when (state) {
            is ApprovalState.AwaitingSignature -> ifExpired(state, event.nowEpochSeconds) {
                ApprovalState.AwaitingTransfer(
                    state.challenge,
                    state.facts.copy(
                        deviceSignature = DeviceSignatureFact.Created(event.fingerprint),
                    ),
                )
            }
            else -> invalid(state)
        }
        ApprovalEvent.SignatureFailed -> failSignature(state)
        ApprovalEvent.ResponsePresented -> transfer(state, TransferFact.PRESENTED)
        ApprovalEvent.TransferDelivered -> transfer(state, TransferFact.DELIVERED)
        ApprovalEvent.TransferFailed -> failTransfer(state)
        is ApprovalEvent.ServerResult -> when (state) {
            is ApprovalState.AwaitingTransfer ->
                ApprovalState.Finished(state.facts.copy(serverVerification = event.result))
            else -> invalid(state)
        }
        ApprovalEvent.Cancel -> ApprovalState.Failed(FailureReason.CANCELLED, factsOf(state))
    }

    private fun begin(event: ApprovalEvent.Begin): ApprovalState {
        if (event.installation.trustState != InstallationTrustState.TRUSTED ||
            event.installation.id != event.challenge.installationId
        ) {
            return ApprovalState.Failed(FailureReason.UNTRUSTED_INSTALLATION, ApprovalFacts())
        }
        if (event.nowEpochSeconds >= event.challenge.expiresAtEpochSeconds) {
            return ApprovalState.Failed(FailureReason.EXPIRED, ApprovalFacts())
        }
        return ApprovalState.Reviewing(event.challenge, ApprovalFacts())
    }

    private inline fun ifExpired(
        state: ApprovalState,
        nowEpochSeconds: Long,
        transition: () -> ApprovalState,
    ): ApprovalState {
        val challenge = when (state) {
            is ApprovalState.Reviewing -> state.challenge
            is ApprovalState.AwaitingAuthentication -> state.challenge
            is ApprovalState.AwaitingSignature -> state.challenge
            else -> return invalid(state)
        }
        return if (nowEpochSeconds >= challenge.expiresAtEpochSeconds) {
            ApprovalState.Failed(FailureReason.EXPIRED, factsOf(state))
        } else {
            transition()
        }
    }

    private fun failAuthentication(state: ApprovalState): ApprovalState =
        if (state is ApprovalState.AwaitingAuthentication) {
            ApprovalState.Failed(
                FailureReason.AUTHENTICATION_FAILED,
                state.facts.copy(
                    localAuthentication = LocalAuthenticationFact.Failed("authentication failed"),
                ),
            )
        } else {
            invalid(state)
        }

    private fun failSignature(state: ApprovalState): ApprovalState =
        if (state is ApprovalState.AwaitingSignature) {
            ApprovalState.Failed(
                FailureReason.SIGNATURE_FAILED,
                state.facts.copy(deviceSignature = DeviceSignatureFact.Failed("signing failed")),
            )
        } else {
            invalid(state)
        }

    private fun transfer(state: ApprovalState, fact: TransferFact): ApprovalState =
        if (state is ApprovalState.AwaitingTransfer) {
            state.copy(facts = state.facts.copy(transfer = fact))
        } else {
            invalid(state)
        }

    private fun failTransfer(state: ApprovalState): ApprovalState =
        if (state is ApprovalState.AwaitingTransfer) {
            ApprovalState.Failed(
                FailureReason.TRANSFER_FAILED,
                state.facts.copy(transfer = TransferFact.FAILED),
            )
        } else {
            invalid(state)
        }

    private fun invalid(state: ApprovalState): ApprovalState =
        ApprovalState.Failed(FailureReason.INVALID_TRANSITION, factsOf(state))

    private fun factsOf(state: ApprovalState): ApprovalFacts = when (state) {
        ApprovalState.Idle -> ApprovalFacts()
        is ApprovalState.Reviewing -> state.facts
        is ApprovalState.AwaitingAuthentication -> state.facts
        is ApprovalState.AwaitingSignature -> state.facts
        is ApprovalState.AwaitingTransfer -> state.facts
        is ApprovalState.Finished -> state.facts
        is ApprovalState.Failed -> state.facts
    }
}
