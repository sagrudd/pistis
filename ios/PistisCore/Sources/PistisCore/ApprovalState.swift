import Foundation

public enum HumanDecision: String, Codable, Sendable {
    case approved
    case denied
}

public enum LocalAuthenticationFact: Equatable, Sendable {
    case notRequested
    case verified(method: UserVerificationMethod, fallbackUsed: Bool)
    case cancelled
    case lockedOut
    case unavailable
    case failed
}

public enum UserVerificationMethod: String, Codable, Sendable {
    case faceID = "face_id"
    case touchID = "touch_id"
    case devicePasscode = "device_passcode"
}

public enum DeviceSignatureFact: Equatable, Sendable {
    case notAttempted
    case created(keyID: String, signatureDigest: SHA256Fingerprint)
    case failed
}

public enum TransferFact: Equatable, Sendable {
    case notAttempted
    case submitted(route: ChallengeRoute, receiptID: String?)
    case failed(route: ChallengeRoute)
}

public enum ServerVerificationFact: Equatable, Sendable {
    case notObserved
    case accepted(evidenceID: EvidenceID)
    case rejected(reason: ServerRejectionReason)
}

public enum ServerRejectionReason: String, Codable, Sendable {
    case invalidSignature = "invalid_signature"
    case revokedDevice = "revoked_device"
    case expired
    case replay
    case policy
    case unknown
}

public struct ApprovalFacts: Equatable, Sendable {
    public let challenge: ApprovalChallenge
    public private(set) var decision: HumanDecision?
    public private(set) var decidedAt: Date?
    public private(set) var localAuthentication: LocalAuthenticationFact
    public private(set) var signature: DeviceSignatureFact
    public private(set) var transfer: TransferFact
    public private(set) var serverVerification: ServerVerificationFact

    public init(challenge: ApprovalChallenge) {
        self.challenge = challenge
        decision = nil
        decidedAt = nil
        localAuthentication = .notRequested
        signature = .notAttempted
        transfer = .notAttempted
        serverVerification = .notObserved
    }

    public mutating func decide(_ decision: HumanDecision, at: Date) throws {
        guard self.decision == nil else { throw ApprovalTransitionError.decisionAlreadyRecorded }
        guard at >= challenge.issuedAt, at < challenge.expiresAt else {
            throw ApprovalTransitionError.challengeExpired
        }
        self.decision = decision
        decidedAt = at
    }

    public mutating func recordLocalAuthentication(_ fact: LocalAuthenticationFact) throws {
        guard decision == .approved else { throw ApprovalTransitionError.notApproved }
        guard localAuthentication == .notRequested else {
            throw ApprovalTransitionError.localAuthenticationAlreadyRecorded
        }
        localAuthentication = fact
    }

    public mutating func recordSignature(_ fact: DeviceSignatureFact) throws {
        guard case .verified = localAuthentication else {
            throw ApprovalTransitionError.userVerificationRequired
        }
        guard signature == .notAttempted else {
            throw ApprovalTransitionError.signatureAlreadyRecorded
        }
        signature = fact
    }

    public mutating func recordTransfer(_ fact: TransferFact) throws {
        guard case .created = signature else { throw ApprovalTransitionError.signatureRequired }
        guard transfer == .notAttempted else {
            throw ApprovalTransitionError.transferAlreadyRecorded
        }
        transfer = fact
    }

    public mutating func recordServerVerification(_ fact: ServerVerificationFact) throws {
        guard case .submitted = transfer else { throw ApprovalTransitionError.transferRequired }
        guard serverVerification == .notObserved else {
            throw ApprovalTransitionError.serverVerificationAlreadyRecorded
        }
        serverVerification = fact
    }

    public var isLocallyApproved: Bool {
        decision == .approved
    }

    public var isAcceptedByInstallation: Bool {
        if case .accepted = serverVerification { return true }
        return false
    }
}

public enum ApprovalTransitionError: Error, Equatable, Sendable {
    case decisionAlreadyRecorded
    case challengeExpired
    case notApproved
    case localAuthenticationAlreadyRecorded
    case userVerificationRequired
    case signatureAlreadyRecorded
    case signatureRequired
    case transferAlreadyRecorded
    case transferRequired
    case serverVerificationAlreadyRecorded
}
