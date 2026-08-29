import CryptoKit
import Foundation
import XCTest

final class IOSReleaseManifestTests: XCTestCase {
    private struct ReleaseManifest: Decodable {
        let schemaVersion: String
        let productID: String
        let repository: String
        let version: String
        let bundleIdentifier: String
        let marketingVersion: String
        let buildNumber: String
        let targetName: String
        let xcodeProjectPath: String
        let xcodeProjectSHA256: String
        let infoPlistPath: String
        let infoPlistSHA256: String
        let buildConfigurations: [String]

        enum CodingKeys: String, CodingKey {
            case schemaVersion = "schema_version"
            case productID = "product_id"
            case repository
            case version
            case bundleIdentifier = "bundle_identifier"
            case marketingVersion = "marketing_version"
            case buildNumber = "build_number"
            case targetName = "target_name"
            case xcodeProjectPath = "xcode_project_path"
            case xcodeProjectSHA256 = "xcode_project_sha256"
            case infoPlistPath = "info_plist_path"
            case infoPlistSHA256 = "info_plist_sha256"
            case buildConfigurations = "build_configurations"
        }
    }

    func testReleaseManifestBindsTheFirstPartyIOSProduct() throws {
        let (manifest, repositoryRoot) = try loadManifest()

        XCTAssertEqual(manifest.schemaVersion, "mnemosyne.pistis.ios-release-manifest.v1")
        XCTAssertEqual(manifest.productID, "pistis-ios")
        XCTAssertEqual(manifest.repository, "sagrudd/pistis")
        XCTAssertEqual(manifest.version, "0.25.0+59")
        XCTAssertEqual(manifest.bundleIdentifier, "org.mnemosynebiosciences.pistis")
        XCTAssertEqual(manifest.marketingVersion, "0.25.0")
        XCTAssertEqual(manifest.buildNumber, "59")
        XCTAssertEqual(manifest.targetName, "Pistis")
        XCTAssertEqual(manifest.buildConfigurations, ["Debug", "Release"])

        try assertWitness(
            repositoryRoot.appendingPathComponent(manifest.xcodeProjectPath),
            hasSHA256: manifest.xcodeProjectSHA256
        )
        try assertWitness(
            repositoryRoot.appendingPathComponent(manifest.infoPlistPath),
            hasSHA256: manifest.infoPlistSHA256
        )
    }

    func testEveryPistisAppBuildConfigurationMatchesTheReleaseManifest() throws {
        let (manifest, repositoryRoot) = try loadManifest()
        let projectURL = repositoryRoot.appendingPathComponent(manifest.xcodeProjectPath)
        let project = try String(contentsOf: projectURL, encoding: .utf8)

        let appConfigurationIDs = try appConfigurationIdentifiers(
            named: manifest.targetName,
            in: project
        )
        XCTAssertEqual(Set(appConfigurationIDs.keys), Set(manifest.buildConfigurations))

        for configuration in manifest.buildConfigurations {
            let identifier = try XCTUnwrap(appConfigurationIDs[configuration])
            let settings = try buildSettings(for: identifier, named: configuration, in: project)
            XCTAssertEqual(settings["PRODUCT_BUNDLE_IDENTIFIER"], manifest.bundleIdentifier)
            XCTAssertEqual(settings["MARKETING_VERSION"], manifest.marketingVersion)
            XCTAssertEqual(settings["CURRENT_PROJECT_VERSION"], manifest.buildNumber)
            XCTAssertEqual(settings["INFOPLIST_FILE"], "Info.plist")
        }
    }

    func testInfoPlistDelegatesReleaseIdentityToReviewedBuildSettings() throws {
        let (manifest, repositoryRoot) = try loadManifest()
        let plistURL = repositoryRoot.appendingPathComponent(manifest.infoPlistPath)
        let data = try Data(contentsOf: plistURL)
        let plist = try XCTUnwrap(
            PropertyListSerialization.propertyList(from: data, format: nil)
                as? [String: Any]
        )

        XCTAssertEqual(plist["CFBundleIdentifier"] as? String, "$(PRODUCT_BUNDLE_IDENTIFIER)")
        XCTAssertEqual(plist["CFBundleShortVersionString"] as? String, "$(MARKETING_VERSION)")
        XCTAssertEqual(plist["CFBundleVersion"] as? String, "$(CURRENT_PROJECT_VERSION)")
    }

    private func loadManifest() throws -> (ReleaseManifest, URL) {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let manifestURL = repositoryRoot.appendingPathComponent(
            "ios/PistisApp/pistis-ios-release.json"
        )
        let decoder = JSONDecoder()
        return (try decoder.decode(ReleaseManifest.self, from: Data(contentsOf: manifestURL)), repositoryRoot)
    }

    private func assertWitness(_ url: URL, hasSHA256 expected: String) throws {
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path), "missing witness: \(url.path)")
        let digest = SHA256.hash(data: try Data(contentsOf: url))
            .map { String(format: "%02x", $0) }
            .joined()
        XCTAssertEqual(digest, expected, "stale release witness: \(url.path)")
    }

    private func appConfigurationIdentifiers(
        named targetName: String,
        in project: String
    ) throws -> [String: String] {
        let targetPattern = #"(?s)[A-F0-9]+ /\* "#
            + NSRegularExpression.escapedPattern(for: targetName)
            + #" \*/ = \{.*?isa = PBXNativeTarget;.*?buildConfigurationList = ([A-F0-9]+) /\* Build configuration list for PBXNativeTarget \""#
            + NSRegularExpression.escapedPattern(for: targetName)
            + #"\" \*/;.*?\};"#
        let targetMatch = try firstMatch(targetPattern, in: project)
        let listIdentifier = try capturedString(1, match: targetMatch, in: project)
        let listPattern = #"(?s)"# + listIdentifier
            + #" /\* Build configuration list for PBXNativeTarget \""#
            + NSRegularExpression.escapedPattern(for: targetName)
            + #"\" \*/ = \{.*?buildConfigurations = \((.*?)\);.*?\};"#
        let listMatch = try firstMatch(listPattern, in: project)
        let entries = try capturedString(1, match: listMatch, in: project)
        let entryPattern = #"([A-F0-9]+) /\* ([^*]+) \*/"#
        let expression = try NSRegularExpression(pattern: entryPattern)
        let range = NSRange(entries.startIndex..., in: entries)
        return try Dictionary(uniqueKeysWithValues: expression.matches(in: entries, range: range).map {
            (try capturedString(2, match: $0, in: entries), try capturedString(1, match: $0, in: entries))
        })
    }

    private func buildSettings(
        for identifier: String,
        named configuration: String,
        in project: String
    ) throws -> [String: String] {
        let pattern = #"(?s)"# + identifier + #" /\* "#
            + NSRegularExpression.escapedPattern(for: configuration)
            + #" \*/ = \{.*?buildSettings = \{(.*?)\};.*?name = "#
            + NSRegularExpression.escapedPattern(for: configuration) + #";.*?\};"#
        let match = try firstMatch(pattern, in: project)
        let block = try capturedString(1, match: match, in: project)
        let settingPattern = #"(?m)^\s*([A-Z][A-Z0-9_]*) = (?:\"([^\"]*)\"|([^;]*));"#
        let expression = try NSRegularExpression(pattern: settingPattern)
        let range = NSRange(block.startIndex..., in: block)
        return try Dictionary(uniqueKeysWithValues: expression.matches(in: block, range: range).map {
            let key = try capturedString(1, match: $0, in: block)
            let quoted = capturedStringIfPresent(2, match: $0, in: block)
            let unquoted = capturedStringIfPresent(3, match: $0, in: block)
            return (key, quoted ?? unquoted ?? "")
        })
    }

    private func firstMatch(_ pattern: String, in source: String) throws -> NSTextCheckingResult {
        let expression = try NSRegularExpression(pattern: pattern)
        return try XCTUnwrap(
            expression.firstMatch(in: source, range: NSRange(source.startIndex..., in: source)),
            "release identity not found in Xcode project"
        )
    }

    private func capturedString(
        _ index: Int,
        match: NSTextCheckingResult,
        in source: String
    ) throws -> String {
        try XCTUnwrap(capturedStringIfPresent(index, match: match, in: source))
    }

    private func capturedStringIfPresent(
        _ index: Int,
        match: NSTextCheckingResult,
        in source: String
    ) -> String? {
        guard match.range(at: index).location != NSNotFound,
              let range = Range(match.range(at: index), in: source)
        else { return nil }
        return String(source[range]).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
