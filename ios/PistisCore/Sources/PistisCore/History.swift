import Foundation

public enum HistoryEventKind: String, Codable, Sendable {
    case requestReceived = "request_received"
    case humanApproved = "human_approved"
    case humanDenied = "human_denied"
    case localAuthentication = "local_authentication"
    case deviceSignature = "device_signature"
    case transfer
    case serverAccepted = "server_accepted"
    case serverRejected = "server_rejected"
}

public enum EvidenceAvailability: String, Codable, Sendable {
    case observed
    case unavailable
    case notApplicable = "not_applicable"
}

public struct HistoryEvent: Codable, Equatable, Sendable {
    public let sequence: UInt
    public let kind: HistoryEventKind
    public let observedAt: Date
    public let summary: String
    public let availability: EvidenceAvailability

    public init(
        sequence: UInt,
        kind: HistoryEventKind,
        observedAt: Date,
        summary: String,
        availability: EvidenceAvailability = .observed
    ) {
        self.sequence = sequence
        self.kind = kind
        self.observedAt = observedAt
        self.summary = summary
        self.availability = availability
    }
}

public struct LocalHistoryRecord: Codable, Equatable, Sendable {
    public let challengeID: ChallengeID
    public let installationID: InstallationID
    public let identityID: IdentityID
    public let purpose: ApprovalPurpose
    public let events: [HistoryEvent]

    public init(
        challengeID: ChallengeID,
        installationID: InstallationID,
        identityID: IdentityID,
        purpose: ApprovalPurpose,
        events: [HistoryEvent]
    ) throws {
        guard !events.isEmpty,
              events.enumerated().allSatisfy({ UInt($0.offset) == $0.element.sequence }),
              zip(events, events.dropFirst()).allSatisfy({ $0.observedAt <= $1.observedAt })
        else {
            throw HistoryValidationError.nonCanonicalTimeline
        }
        self.challengeID = challengeID
        self.installationID = installationID
        self.identityID = identityID
        self.purpose = purpose
        self.events = events
    }
}

public enum HistoryValidationError: Error, Equatable, Sendable {
    case nonCanonicalTimeline
}
