import Foundation
import XCTest
@testable import Pistis

@MainActor
final class SiteRootInstallationRepositoryTests: XCTestCase {
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
}
