import Foundation
import XCTest
@testable import Pistis

@MainActor
final class LocalHistoryRepositoryTests: XCTestCase {
    func testHistoryIsDurableIdempotentAndMinimized() async throws {
        let suite = "pistis-local-history-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let repository = LocalHistoryRepository(defaults: defaults)
        let event = HistoryEvent(
            id: UUID(),
            action: "Device enrolled",
            installation: "Laboratory Jenkins",
            occurredAt: "Exact time not retained locally",
            decision: "Verified",
            signature: "Secure Enclave registration verified",
            transfer: "Authority receipt installed locally",
            verification: "Authority receipt verified"
        )

        var changes = 0
        let observation = NotificationCenter.default.publisher(
            for: LocalHistoryRepository.historyDidChangeNotification
        ).sink { _ in changes += 1 }
        defer { observation.cancel() }

        let anotherEvent = HistoryEvent(
            id: UUID(),
            action: event.action,
            installation: "Another installation",
            occurredAt: event.occurredAt,
            decision: event.decision,
            signature: event.signature,
            transfer: event.transfer,
            verification: event.verification
        )
        try repository.record(event)
        try repository.record(anotherEvent)
        for _ in 0..<100 {
            try repository.record(event)
            try repository.record(anotherEvent)
        }
        XCTAssertEqual(changes, 2, "Duplicate records must not trigger a refresh loop")

        let records = try repository.records()
        XCTAssertEqual(records, [event, anotherEvent])
        let encoded = try XCTUnwrap(
            defaults.data(
                forKey: "org.mnemosynebiosciences.pistis.local-history.v1"
            )
        )
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("receipt_cose"))
    }
}
