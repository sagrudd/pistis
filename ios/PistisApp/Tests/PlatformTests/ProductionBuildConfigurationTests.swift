import Foundation
import XCTest

final class ProductionBuildConfigurationTests: XCTestCase {
    func testMigratedReleaseBuildConsumesOneExactRootArtifact() throws {
        let script = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("../../Scripts/build-site-root-release.sh")
            .standardizedFileURL
        let source = try String(contentsOf: script, encoding: .utf8)
        XCTAssertTrue(source.contains("PISTIS_MONAS_SITE_ROOT_AUTHORITY_TRUST_MODE='site-root-generation-v1'"))
        XCTAssertTrue(source.contains("PISTIS_MONAS_SITE_ROOT_AUTHORITY_SPKI_SHA256=''"))
        XCTAssertTrue(source.contains("openssl x509 -inform DER"))
        XCTAssertTrue(source.contains("openssl dgst -sha256 -binary"))
        XCTAssertTrue(source.contains("CURRENT_PROJECT_VERSION=4"))
        XCTAssertFalse(source.contains("bootstrap-leaf-spki-v1"))
    }
}
