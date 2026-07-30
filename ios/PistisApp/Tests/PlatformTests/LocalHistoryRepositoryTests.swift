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

        try repository.record(event)
        try repository.record(event)

        let records = try repository.records()
        XCTAssertEqual(records, [event])
        let encoded = try XCTUnwrap(
            defaults.data(
                forKey: "org.mnemosynebiosciences.pistis.local-history.v1"
            )
        )
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("receipt_cose"))
    }
}
