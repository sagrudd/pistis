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

    func testIPhoneSimulatorIsConfinedToTheTestTarget() throws {
        let platformTests = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let appRoot = platformTests.deletingLastPathComponent().deletingLastPathComponent()
        let simulator = platformTests.appendingPathComponent(
            "MonasFirstWebLoginIPhoneSimulatorTests.swift"
        )
        XCTAssertTrue(FileManager.default.fileExists(atPath: simulator.path))

        let productionSources = appRoot.appendingPathComponent("Sources")
        let releaseScript = appRoot.appendingPathComponent("Scripts/build-pistis-release.sh")
        let plist = appRoot.appendingPathComponent("Info.plist")
        for root in [productionSources, releaseScript, plist] {
            let values: [URL]
            if root.hasDirectoryPath {
                values = FileManager.default.enumerator(
                    at: root,
                    includingPropertiesForKeys: nil
                )?.compactMap { $0 as? URL } ?? []
            } else {
                values = [root]
            }
            for value in values where value.pathExtension == "swift"
                || value.pathExtension == "sh" || value.pathExtension == "plist"
            {
                let source = try String(contentsOf: value, encoding: .utf8)
                XCTAssertFalse(
                    source.contains("MonasFirstWebLoginIPhoneSimulator"),
                    "test-only iPhone simulator leaked into \(value.path)"
                )
            }
        }
    }
}
