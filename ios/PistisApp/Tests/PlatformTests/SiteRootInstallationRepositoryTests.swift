import Foundation
import XCTest

@testable import Pistis

@MainActor
final class SiteRootInstallationRepositoryTests: XCTestCase {
    func testInitialSiteTrustCompletionRoutesToRecordedSetupProgress() {
        let completion = SiteRootDelegationCoordinator.Completion.siteTrustEstablished

        XCTAssertEqual(completion.heading, "Site Trust established")
        XCTAssertEqual(completion.evidenceLabel, "Setup state")
        XCTAssertEqual(completion.evidenceValue, "Setup in progress")
        XCTAssertEqual(completion.actionTitle, "View setup progress")
        XCTAssertTrue(completion.detail.contains("cannot authenticate or approve work"))
    }

    func testCompletedSessionRoutesToItsInstallationWithoutClaimingSetupProgress() {
        let completion = SiteRootDelegationCoordinator.Completion.sessionEstablished

        XCTAssertEqual(completion.heading, "Site Root ceremony complete")
        XCTAssertEqual(completion.evidenceLabel, "Custody rewrap")
        XCTAssertEqual(completion.evidenceValue, "Submitted")
        XCTAssertEqual(completion.actionTitle, "View installation")
    }

    func testRecordsRejectUnknownStorageProfile() throws {
        let suite = "pistis-site-root-installation-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let repository = SiteRootInstallationRepository(defaults: defaults)

        let invalid = """
        [{"storageProfile":3,"id":"00000000-0000-0000-0000-000000000001","authorityHost":"monas.example.test","redactedReference":"abc123…def4","recordedAt":0}]
        """
        defaults.set(
            try XCTUnwrap(invalid.data(using: .utf8)),
            forKey: "org.mnemosynebiosciences.pistis.site-root-installations.v1"
        )

        XCTAssertThrowsError(try repository.records())
    }

  func testThreeLegacyHostDuplicatesMigrateToOneWithoutLosingEvidence() throws {
    let suite = "pistis-site-root-dedupe-tests-\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let key = "org.mnemosynebiosciences.pistis.site-root-installations.v1"
    let legacy: [[String: Any]] = [
      [
        "storageProfile": 1, "id": "00000000-0000-0000-0000-000000000003",
        "authorityHost": "192.168.1.192", "redactedReference": "third…0003", "recordedAt": 3_000,
        "setupPhase": "authority-custody-required",
      ],
      [
        "storageProfile": 1, "id": "00000000-0000-0000-0000-000000000001",
        "authorityHost": "192.168.1.192.", "redactedReference": "first…0001", "recordedAt": 1_000,
        "setupPhase": "identity-enrolment-required",
      ],
      [
        "storageProfile": 1, "id": "00000000-0000-0000-0000-000000000002",
        "authorityHost": "192.168.1.192", "redactedReference": "second…0002", "recordedAt": 2_000,
        "setupPhase": "authority-custody-required",
      ],
    ]
    defaults.set(try JSONSerialization.data(withJSONObject: legacy), forKey: key)

    let records = try SiteRootInstallationRepository(defaults: defaults).records()
    XCTAssertEqual(records.count, 1)
    XCTAssertEqual(records[0].id.uuidString, "00000000-0000-0000-0000-000000000001")
    XCTAssertEqual(records[0].authorityHost, "192.168.1.192")
    XCTAssertEqual(records[0].setupPhase, .identityEnrolmentRequired)
    XCTAssertEqual(records[0].redactedReference, "third…0003")
    XCTAssertEqual(
      records[0].evidence.map(\.redactedReference), ["first…0001", "second…0002", "third…0003"])
  }

  func testRepeatedObservationCannotRegressPhaseAndDistinctHostsRemainDistinct() throws {
    let suite = "pistis-site-root-monotonic-tests-\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let repository = SiteRootInstallationRepository(defaults: defaults)
    try repository.recordRecoveredFirstCeremony(
      authorityHost: "MONAS.EXAMPLE.TEST.", redactedReference: "first…0001",
      registeredAt: Date(timeIntervalSince1970: 1)
    )
    try repository.recordAuthorityCustodyCompleted(authorityHost: "monas.example.test")
    try repository.recordRecoveredFirstCeremony(
      authorityHost: "monas.example.test", redactedReference: "second…0002",
      registeredAt: Date(timeIntervalSince1970: 2)
    )
    try repository.recordRecoveredFirstCeremony(
      authorityHost: "other.example.test", redactedReference: "other…0003",
      registeredAt: Date(timeIntervalSince1970: 3)
    )

    let records = try repository.records()
    XCTAssertEqual(records.count, 2)
    let monas = try XCTUnwrap(records.first { $0.authorityHost == "monas.example.test" })
    XCTAssertEqual(monas.setupPhase, .identityEnrolmentRequired)
    XCTAssertEqual(monas.evidence.count, 2)
  }

    func testRecordValidationNeverAcceptsAURLOrRawReference() {
        XCTAssertThrowsError(
            try IncompleteSiteRootInstallation(
                authorityHost: "https://monas.example.test",
                redactedReference: "unredacted/reference"
            )
        )
    }

    func testLegacyRecordDefaultsToAuthorityCustodyAndTransitionsExactlyOnce() throws {
        let suite = "pistis-site-root-phase-tests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let repository = SiteRootInstallationRepository(defaults: defaults)
        try repository.recordRecoveredFirstCeremony(
            authorityHost: "monas.example.test", redactedReference: "abc123…def4",
            registeredAt: Date(timeIntervalSince1970: 1_000)
        )
        let key = "org.mnemosynebiosciences.pistis.site-root-installations.v1"
        var objects = try XCTUnwrap(
            JSONSerialization.jsonObject(with: try XCTUnwrap(defaults.data(forKey: key)))
                as? [[String: Any]]
        )
        objects[0].removeValue(forKey: "setupPhase")
        defaults.set(try JSONSerialization.data(withJSONObject: objects), forKey: key)

        XCTAssertEqual(try repository.records().first?.setupPhase, .authorityCustodyRequired)
        try repository.recordAuthorityCustodyCompleted(authorityHost: "monas.example.test")
        XCTAssertEqual(try repository.records().first?.setupPhase, .identityEnrolmentRequired)
    XCTAssertThrowsError(
      try repository.recordAuthorityCustodyCompleted(
            authorityHost: "monas.example.test"
        ))
    }

    func testReconciliationResponseAcceptsOnlyProofConsumedOrCompleted() throws {
        let accepted = """
        {"schema":"monas.site-root-genesis-installation-status.v1","state":"proof-consumed","redacted_reference":"abc123…def4","registered_at_unix_millis":1000}
        """
        let value = try MonasInstallationStatusResponse(
            data: try XCTUnwrap(accepted.data(using: .utf8))
        ).value
        XCTAssertEqual(value.redactedReference, "abc123…def4")
        XCTAssertEqual(value.registeredAt, Date(timeIntervalSince1970: 1))

        let rejected = accepted.replacingOccurrences(of: "proof-consumed", with: "registered")
        XCTAssertThrowsError(
            try MonasInstallationStatusResponse(
                data: try XCTUnwrap(rejected.data(using: .utf8))
            ).value
        )
    }
}
