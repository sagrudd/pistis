import Foundation
import XCTest

final class ProductionBuildConfigurationTests: XCTestCase {
    func testReleaseBuildIsHostAgnostic() throws {
        let script = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("../../Scripts/build-pistis-release.sh")
            .standardizedFileURL
        let source = try String(contentsOf: script, encoding: .utf8)
        XCTAssertTrue(source.contains("usage: $0 [DERIVED_DATA_PATH]"))
        XCTAssertTrue(source.contains("Host origin, TLS pins, Site Root certificates"))
        XCTAssertFalse(source.contains("PISTIS_MONAS_SITE_ROOT_AUTHORITY_ORIGIN"))
        XCTAssertFalse(source.contains("PISTIS_MONAS_SITE_ROOT_AUTHORITY_ROOT_DER"))
        XCTAssertFalse(source.contains("192.168.1.192"))
    }

    func testInfoPlistContainsNoDeploymentSpecificSiteRootIdentity() throws {
        let plist = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("../../Info.plist")
            .standardizedFileURL
        let source = try String(contentsOf: plist, encoding: .utf8)
        XCTAssertFalse(source.contains("PistisMonasSiteRootAuthorityOrigin"))
        XCTAssertFalse(source.contains("PistisMonasSiteRootAuthorityRootDERB64URL"))
        XCTAssertFalse(source.contains("PISTIS_MONAS_SITE_ROOT_AUTHORITY"))
    }
}
