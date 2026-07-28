import Testing
@testable import PistisCore

@Test func approvalFactsKeepHumanIntentSeparateFromAcceptance() throws {
    var facts = ApprovalFacts(challenge: Fixtures.challenge())
    try facts.decide(.approved, at: Fixtures.now.addingTimeInterval(1))

    #expect(facts.isLocallyApproved)
    #expect(!facts.isAcceptedByInstallation)
    #expect(facts.signature == .notAttempted)
    #expect(facts.serverVerification == .notObserved)

    try facts.recordLocalAuthentication(.verified(method: .faceID, fallbackUsed: false))
    try facts.recordSignature(.created(
        keyID: "device-key-1",
        signatureDigest: Fixtures.fingerprintB
    ))
    try facts.recordTransfer(.submitted(route: .qr, receiptID: nil))
    #expect(!facts.isAcceptedByInstallation)

    try facts.recordServerVerification(.accepted(
        evidenceID: try EvidenceID(validating: "evidence-1")
    ))
    #expect(facts.isAcceptedByInstallation)
}

@Test func denialRequiresLocalAuthenticationAndSignature() throws {
    var facts = ApprovalFacts(challenge: Fixtures.challenge())
    try facts.decide(.denied, at: Fixtures.now.addingTimeInterval(1))
    try facts.recordLocalAuthentication(.verified(method: .faceID, fallbackUsed: false))
    try facts.recordSignature(.created(
        keyID: "device-key-1",
        signatureDigest: Fixtures.fingerprintB
    ))
    #expect(facts.decision == .denied)
}

@Test func signatureRequiresSuccessfulFreshUserVerification() throws {
    var facts = ApprovalFacts(challenge: Fixtures.challenge())
    try facts.decide(.approved, at: Fixtures.now.addingTimeInterval(1))
    try facts.recordLocalAuthentication(.cancelled)
    #expect(throws: ApprovalTransitionError.userVerificationRequired) {
        try facts.recordSignature(.created(
            keyID: "device-key-1",
            signatureDigest: Fixtures.fingerprintB
        ))
    }
}

@Test func expiredDecisionIsRejected() {
    var facts = ApprovalFacts(challenge: Fixtures.challenge())
    #expect(throws: ApprovalTransitionError.challengeExpired) {
        try facts.decide(.approved, at: Fixtures.now.addingTimeInterval(120))
    }
}

@Test(arguments: [ChallengeRoute.qr, .directLocal])
func qrAndDirectLocalUseSameReducer(route: ChallengeRoute) throws {
    let reducer = ApprovalFlowReducer()
    let challenge = Fixtures.challenge(route: route)
    var state = reducer.reduce(
        state: .idle,
        event: .acquired(
            challenge: challenge,
            identity: Fixtures.identity(),
            installation: Fixtures.installation(),
            now: Fixtures.now.addingTimeInterval(1)
        )
    )
    guard case .awaitingDecision = state else {
        Issue.record("challenge did not reach decision")
        return
    }
    state = reducer.reduce(
        state: state,
        event: .decide(.approved, at: Fixtures.now.addingTimeInterval(2))
    )
    state = reducer.reduce(
        state: state,
        event: .localAuthentication(.verified(method: .faceID, fallbackUsed: false))
    )
    state = reducer.reduce(
        state: state,
        event: .signature(.created(keyID: "key", signatureDigest: Fixtures.fingerprintB))
    )
    state = reducer.reduce(
        state: state,
        event: .transfer(.submitted(route: route, receiptID: "receipt"))
    )
    guard case let .awaitingServerVerification(facts) = state else {
        Issue.record("flow did not reach server verification")
        return
    }
    #expect(facts.challenge.route == route)
    #expect(facts.isLocallyApproved)
    #expect(!facts.isAcceptedByInstallation)
}

@Test func backgroundingCancelsPendingCeremony() {
    let reducer = ApprovalFlowReducer()
    let state = reducer.reduce(
        state: .awaitingDecision(ApprovalFacts(challenge: Fixtures.challenge())),
        event: .backgrounded
    )
    #expect(state == .cancelled)
}

@Test func untrustedAndChangedInstallationsFailClosed() throws {
    let reducer = ApprovalFlowReducer()
    let untrusted = Fixtures.installation(paired: false)
    let state = reducer.reduce(
        state: .idle,
        event: .acquired(
            challenge: Fixtures.challenge(),
            identity: Fixtures.identity(),
            installation: untrusted,
            now: Fixtures.now.addingTimeInterval(1)
        )
    )
    #expect(state == .failed(.invalidChallenge(.installationNotTrusted(.new))))
}
