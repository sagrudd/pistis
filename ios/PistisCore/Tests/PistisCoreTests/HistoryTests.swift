import Testing
@testable import PistisCore

@Test func historyRequiresOrderedContiguousTimeline() throws {
    let valid = [
        HistoryEvent(
            sequence: 0,
            kind: .requestReceived,
            observedAt: Fixtures.now,
            summary: "Request received"
        ),
        HistoryEvent(
            sequence: 1,
            kind: .humanApproved,
            observedAt: Fixtures.now.addingTimeInterval(1),
            summary: "Approved on this device"
        ),
    ]
    let record = try LocalHistoryRecord(
        challengeID: Fixtures.challengeID,
        installationID: Fixtures.installationID,
        identityID: Fixtures.identityID,
        purpose: .login,
        events: valid
    )
    #expect(record.events.count == 2)

    let invalid = [
        valid[0],
        HistoryEvent(
            sequence: 2,
            kind: .serverAccepted,
            observedAt: Fixtures.now.addingTimeInterval(1),
            summary: "Accepted"
        ),
    ]
    #expect(throws: HistoryValidationError.nonCanonicalTimeline) {
        try LocalHistoryRecord(
            challengeID: Fixtures.challengeID,
            installationID: Fixtures.installationID,
            identityID: Fixtures.identityID,
            purpose: .login,
            events: invalid
        )
    }
}

@Test func historyRejectsTimeReordering() {
    let events = [
        HistoryEvent(
            sequence: 0,
            kind: .requestReceived,
            observedAt: Fixtures.now.addingTimeInterval(2),
            summary: "Request received"
        ),
        HistoryEvent(
            sequence: 1,
            kind: .humanDenied,
            observedAt: Fixtures.now,
            summary: "Denied"
        ),
    ]
    #expect(throws: HistoryValidationError.nonCanonicalTimeline) {
        try LocalHistoryRecord(
            challengeID: Fixtures.challengeID,
            installationID: Fixtures.installationID,
            identityID: Fixtures.identityID,
            purpose: .login,
            events: events
        )
    }
}
