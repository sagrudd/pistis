import Foundation
import XCTest
@testable import Pistis

@MainActor
final class OnboardingEventJournalTests: XCTestCase {
    func testEventBatchContainsOnlyClosedRedactedFacts() throws {
        let secretReference = "ceremony-secret-reference-1234"
        let event = try makeEvent(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            reference: secretReference
        )
        let body = try OnboardingEventUploadBatch(events: [event]).encodedBody()
        let text = String(decoding: body, as: UTF8.self)

        XCTAssertFalse(text.contains(secretReference))
        XCTAssertFalse(text.contains("PISTIS1:"))
        XCTAssertFalse(text.contains("cose_sign1"))
        XCTAssertFalse(text.contains("private_key"))
        XCTAssertFalse(text.contains("token"))
        XCTAssertFalse(text.contains("cookie"))
        XCTAssertFalse(text.contains("monas.example.test"))
        XCTAssertTrue(text.contains(OnboardingEvent.redactedDigest(for: secretReference)))
        XCTAssertEqual(event.failure, nil)
    }

    func testJournalIsBoundedAppendOnlyAndRejectsConflictingIDs() throws {
        let suite = "pistis-onboarding-journal-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let journal = OnboardingEventJournal(
            defaults: defaults,
            nowUnixMillis: { 1_700_000_000_000 + 10_000 }
        )
        var events: [OnboardingEvent] = []

        for index in 0 ..< OnboardingEventJournal.maximumRecords + 6 {
            let event = try makeEvent(
                id: UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", index + 1))!,
                timestamp: UInt64(1_700_000_000_000 + index)
            )
            events.append(event)
            try journal.append(event)
        }

        let retained = try journal.events()
        XCTAssertEqual(retained.count, OnboardingEventJournal.maximumRecords)
        XCTAssertEqual(retained.first?.id, events[6].id)
        try journal.append(events[7])
        XCTAssertEqual(try journal.events().count, retained.count)

        let conflicting = try OnboardingEvent(
            id: events[7].id,
            attemptID: events[7].attemptID,
            flow: events[7].flow,
            kind: .completed,
            stage: events[7].stage,
            outcome: .succeeded,
            referenceDigest: nil,
            authority: events[7].authority,
            occurredAtUnixMillis: events[7].occurredAtUnixMillis
        )
        XCTAssertThrowsError(try journal.append(conflicting))

        defaults.set(
            Data(repeating: 0x7f, count: OnboardingEventJournal.maximumEncodedBytes + 1),
            forKey: "org.mnemosynebiosciences.pistis.onboarding-event-journal.v1"
        )
        XCTAssertThrowsError(try journal.events())
    }

    func testUploadAcknowledgesOnlyAcceptedEventsAndRetainsTheRest() async throws {
        let suite = "pistis-onboarding-upload-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let journal = OnboardingEventJournal(
            defaults: defaults,
            nowUnixMillis: { 1_700_000_000_000 + 10_000 }
        )
        let events = try (0 ..< 3).map { index in
            try makeEvent(
                id: UUID(uuidString: String(format: "10000000-0000-0000-0000-%012d", index + 1))!,
                timestamp: UInt64(1_700_000_000_100 + index)
            )
        }
        for event in events { try journal.append(event) }

        let probe = UploadProbe(acknowledge: [events[0].id])
        let client = OnboardingEventUploadClient(
            journal: journal,
            transport: ProbeTransport(probe: probe)
        )
        let uploaded = try await client.uploadPending()
        XCTAssertEqual(uploaded, 1)
        XCTAssertEqual(try journal.pendingEvents().map(\.id), [events[1].id, events[2].id])
        let batches = await probe.batches()
        XCTAssertEqual(batches.count, 1)

        let rejectedProbe = UploadProbe(acknowledge: [UUID()])
        let rejectedClient = OnboardingEventUploadClient(
            journal: journal,
            transport: ProbeTransport(probe: rejectedProbe)
        )
        do {
            _ = try await rejectedClient.uploadPending()
            XCTFail("expected error")
        } catch {
            // Expected.
        }
        XCTAssertEqual(try journal.pendingEvents().map(\.id), [events[1].id, events[2].id])
    }

    func testJournalPurgesEventsAtFortyEightHours() throws {
        let suite = "pistis-onboarding-journal-retention-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let now: UInt64 = 1_700_000_000_000
        let journal = OnboardingEventJournal(defaults: defaults, nowUnixMillis: { now })
        try journal.append(try makeEvent(timestamp: now - OnboardingEventJournal.retentionMillis - 1))
        try journal.append(try makeEvent(timestamp: now - OnboardingEventJournal.retentionMillis + 1))

        XCTAssertEqual(try journal.events().count, 1)
        let retentionMillis: UInt64 = 48 * 60 * 60 * 1_000
        let later = OnboardingEventJournal(
            defaults: defaults,
            nowUnixMillis: { now + retentionMillis }
        )
        XCTAssertTrue(try later.events().isEmpty)
    }

    func testSiteRootAcceptanceEmitsOneRedactedEventAfterStrictParsing() throws {
        let recorder = RecordingEventRecorder()
        let coordinator = SiteRootDelegationCoordinator(
            eventRecorder: recorder
        )
        coordinator.accept(qrText: siteRootQR())

        XCTAssertEqual(recorder.events.count, 1)
        let event = try XCTUnwrap(recorder.events.first)
        XCTAssertEqual(event.kind, .qrValidated)
        XCTAssertEqual(event.outcome, .accepted)
        XCTAssertEqual(event.flow, .siteRootDelegation)
        XCTAssertEqual(event.stage, .qrValidation)
        XCTAssertNotNil(event.referenceDigestB64URL)
        XCTAssertFalse(
            event.referenceDigestB64URL?.contains("ceremony-fixture") == true
        )
    }

    func testRejectedQRUsesCoarseFailureWithoutRetainingInput() throws {
        let recorder = RecordingEventRecorder()
        let coordinator = SiteRootDelegationCoordinator(eventRecorder: recorder)
        let qr = "{\"secret_invitation\":\"do-not-retain\"}"
        coordinator.accept(qrText: qr)

        let event = try XCTUnwrap(recorder.events.last)
        XCTAssertEqual(event.kind, .failed)
        XCTAssertEqual(event.failure, .qrValidation)
        let encoded = String(decoding: try JSONEncoder().encode(event), as: UTF8.self)
        XCTAssertFalse(encoded.contains("do-not-retain"))
        XCTAssertFalse(encoded.contains("secret_invitation"))
    }

    private func makeEvent(
        id: UUID = UUID(),
        reference: String? = nil,
        timestamp: UInt64 = 1_700_000_000_000
    ) throws -> OnboardingEvent {
        try OnboardingEvent(
            id: id,
            attemptID: UUID(uuidString: "20000000-0000-0000-0000-000000000001")!,
            flow: .firstDeviceSiteRoot,
            kind: .stageEntered,
            stage: .appAttest,
            outcome: .started,
            referenceDigest: reference.map(OnboardingEvent.redactedDigestData),
            authority: .fixedInstallBroker,
            occurredAtUnixMillis: timestamp
        )
    }

    private func siteRootQR() -> String {
        let delegation = Data(
            "{\"device_key_id\":\"site-root-fixture\",\"proof_profile\":\"pistis-secure-enclave-es256-cose-v1\",\"schema\":\"monas.site-root-delegation.v1\",\"secure_enclave_attestation\":\"not-asserted\",\"site_trust_domain\":\"site-demo-1\"}"
                .utf8
        )
        let base64URL = delegation.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "{\"canonical_delegation_base64url\":\"\(base64URL)\",\"device_key_id\":\"site-root-fixture\",\"reference\":\"ceremony-fixture-1234\",\"schema\":\"monas.site-root-delegation-presentation.v1\",\"submit_url\":\"https://monas.example.test/auth/pistis/site-root-delegations/v1/submit\"}"
    }
}

@MainActor
private final class RecordingEventRecorder: OnboardingEventRecording {
    private(set) var events: [OnboardingEvent] = []

    func append(_ event: OnboardingEvent) throws {
        events.append(event)
    }
}

private actor UploadProbe {
    private let acknowledge: [UUID]
    private var captured: [OnboardingEventUploadBatch] = []

    init(acknowledge: [UUID]) {
        self.acknowledge = acknowledge
    }

    func receipt(for batch: OnboardingEventUploadBatch) async throws
        -> OnboardingEventUploadReceipt
    {
        captured.append(batch)
        return try OnboardingEventUploadReceipt(acceptedEventIDs: acknowledge)
    }

    func batches() -> [OnboardingEventUploadBatch] {
        captured
    }
}

private struct ProbeTransport: OnboardingEventUploadTransport {
    let probe: UploadProbe

    func upload(
        _ batch: OnboardingEventUploadBatch
    ) async throws -> OnboardingEventUploadReceipt {
        try await probe.receipt(for: batch)
    }
}
