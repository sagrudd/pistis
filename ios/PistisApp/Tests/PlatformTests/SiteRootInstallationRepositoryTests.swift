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
        [{"storageProfile":2,"id":"00000000-0000-0000-0000-000000000001","authorityHost":"monas.example.test","redactedReference":"abc123…def4","recordedAt":0}]
        """
        defaults.set(
            try XCTUnwrap(invalid.data(using: .utf8)),
            forKey: "org.mnemosynebiosciences.pistis.site-root-installations.v1"
        )

        XCTAssertThrowsError(try repository.records())
    }

    func testRecordValidationNeverAcceptsAURLOrRawReference() {
        XCTAssertThrowsError(
            try IncompleteSiteRootInstallation(
                authorityHost: "https://monas.example.test",
                redactedReference: "unredacted/reference"
            )
        )
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
