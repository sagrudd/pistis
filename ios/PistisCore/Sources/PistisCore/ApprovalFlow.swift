import Foundation

public enum ApprovalFlowState: Equatable, Sendable {
    case idle
    case validating(route: ChallengeRoute)
    case awaitingDecision(ApprovalFacts)
    case awaitingLocalAuthentication(ApprovalFacts)
    case awaitingSignature(ApprovalFacts)
    case awaitingTransfer(ApprovalFacts)
    case awaitingServerVerification(ApprovalFacts)
    case finished(ApprovalFacts)
    case cancelled
    case failed(ApprovalFlowFailure)
}

public enum ApprovalFlowFailure: Equatable, Sendable {
    case invalidChallenge(ChallengeValidationError)
    case localAuthentication(LocalAuthenticationFact)
    case signature
    case transfer(ChallengeRoute)
    case interrupted
}

public enum ApprovalFlowEvent: Sendable {
    case acquired(
        challenge: ApprovalChallenge,
        identity: ExternalIdentity?,
        installation: Installation?,
        now: Date
    )
    case decide(HumanDecision, at: Date)
    case localAuthentication(LocalAuthenticationFact)
    case signature(DeviceSignatureFact)
    case transfer(TransferFact)
    case serverVerification(ServerVerificationFact)
    case backgrounded
    case reset
}

public struct ApprovalFlowReducer: Sendable {
    public init() {}

    public func reduce(
        state: ApprovalFlowState,
        event: ApprovalFlowEvent
    ) -> ApprovalFlowState {
        switch (state, event) {
        case (_, .reset):
            return .idle
        case (.idle, let .acquired(challenge, identity, installation, now)):
            do {
                try challenge.validateForPresentation(
                    now: now,
                    identity: identity,
                    installation: installation
                )
                return .awaitingDecision(ApprovalFacts(challenge: challenge))
            } catch let error as ChallengeValidationError {
                return .failed(.invalidChallenge(error))
            } catch {
                return .failed(.interrupted)
            }
        case (.awaitingDecision(var facts), let .decide(decision, at)):
            do {
                try facts.decide(decision, at: at)
                return decision == .denied ? .finished(facts) : .awaitingLocalAuthentication(facts)
            } catch {
                return .failed(.interrupted)
            }
        case (.awaitingLocalAuthentication(var facts), let .localAuthentication(fact)):
            do {
                try facts.recordLocalAuthentication(fact)
                if case .verified = fact {
                    return .awaitingSignature(facts)
                }
                return .failed(.localAuthentication(fact))
            } catch {
                return .failed(.interrupted)
            }
        case (.awaitingSignature(var facts), let .signature(fact)):
            do {
                try facts.recordSignature(fact)
                if case .created = fact {
                    return .awaitingTransfer(facts)
                }
                return .failed(.signature)
            } catch {
                return .failed(.interrupted)
            }
        case (.awaitingTransfer(var facts), let .transfer(fact)):
            do {
                try facts.recordTransfer(fact)
                if case .submitted = fact {
                    return .awaitingServerVerification(facts)
                }
                if case let .failed(route) = fact {
                    return .failed(.transfer(route))
                }
                return .failed(.interrupted)
            } catch {
                return .failed(.interrupted)
            }
        case (.awaitingServerVerification(var facts), let .serverVerification(fact)):
            do {
                try facts.recordServerVerification(fact)
                return .finished(facts)
            } catch {
                return .failed(.interrupted)
            }
        case (.awaitingDecision, .backgrounded),
             (.awaitingLocalAuthentication, .backgrounded),
             (.awaitingSignature, .backgrounded),
             (.awaitingTransfer, .backgrounded),
             (.awaitingServerVerification, .backgrounded):
            return .cancelled
        default:
            return state
        }
    }
}
