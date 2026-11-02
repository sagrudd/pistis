import CryptoKit
import Foundation
import PistisCore
import XCTest
@testable import Pistis

final class SiteRootTrustAdoptionContractTests: XCTestCase {
    func testChangedTLSLeafPinIsNotAnAuthorisedDeviceReplacement() throws {
        let enrolled = try enrollment(marker: 0x41, pin: 0x21)
        let proposedSuccessor = try AuthenticatedEnrollmentOutput(
            trust: enrolled.trust,
            responseContext: enrolled.responseContext,
            allowedHosts: enrolled.allowedHosts,
            httpsOrigin: enrolled.httpsOrigin,
            tlsSPKISHA256: Data(repeating: 0x22, count: 32)
        )

        XCTAssertThrowsError(
            try InstallationTrustKeychain.firstInstallDisposition(
                existing: enrolled,
                proposed: proposedSuccessor
            )
        ) { error in
            XCTAssertEqual(error as? PlatformFailure, .invalidConfiguration)
        }

        // The pure predicate does not mutate either value. Persistence and
        // selected-install state are outside this test's coverage.
        XCTAssertEqual(enrolled.tlsSPKISHA256, Data(repeating: 0x21, count: 32))
        XCTAssertEqual(enrolled.trust.installationID, Data(repeating: 0x41, count: 16))
    }

    func testEnrolmentFactoryRetainsLeafPinAndRelocationRequiresRootPolicy() throws {
        let enrolled = try enrollment(marker: 0x51, pin: 0x31)
        let transport = try XCTUnwrap(
            ProductionMonasSiteRootTransportFactory.make(verifiedEnrollment: enrolled)
        )

        XCTAssertEqual(transport.genesisAuthorityOrigin?.absoluteString, enrolled.httpsOrigin)
        XCTAssertThrowsError(
            try transport.siteOriginRelocationTransport(
                targetOrigin: URL(string: "https://successor.example.test")!
            )
        ) { error in
            XCTAssertEqual(error as? PlatformFailure, .siteRootAuthorityUnavailable)
        }

        // The runtime-profile helper parses this caller-supplied dictionary;
        // this test does not authenticate the profile or imply adoption.
        let fixture = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("../Fixtures/pistis-example-test.der")
            .standardizedFileURL
        let rootDER = try Data(contentsOf: fixture)
        let fingerprint = Data(SHA256.hash(data: rootDER))
        let profile: [String: Any] = [
            MonasSiteRootAuthorityConfiguration.infoDictionaryKey: enrolled.httpsOrigin,
            MonasSiteRootAuthorityConfiguration.trustModeInfoDictionaryKey:
                MonasSiteRootAuthorityConfiguration.siteRootTrustMode,
            MonasSiteRootAuthorityConfiguration.spkiInfoDictionaryKey: "",
            MonasSiteRootAuthorityConfiguration.rootDERInfoDictionaryKey:
                base64URL(rootDER),
            MonasSiteRootAuthorityConfiguration.rootFingerprintInfoDictionaryKey:
                base64URL(fingerprint),
            MonasSiteRootAuthorityConfiguration.rootGenerationInfoDictionaryKey: "8",
        ]
        XCTAssertTrue(
            ProductionMonasSiteRootTransportFactory.make(
                verifiedRuntimeProfile: profile
            ) is MonasSiteRootDelegationTransport
        )

        let retainedTransport = try XCTUnwrap(
            ProductionMonasSiteRootTransportFactory.make(verifiedEnrollment: enrolled)
        )
        XCTAssertEqual(retainedTransport.genesisAuthorityOrigin, transport.genesisAuthorityOrigin)
        XCTAssertThrowsError(
            try retainedTransport.siteOriginRelocationTransport(
                targetOrigin: URL(string: "https://successor.example.test")!
            )
        )
    }

    private func enrollment(marker: UInt8, pin: UInt8) throws
        -> AuthenticatedEnrollmentOutput
    {
        let trust = try InstallationTrustRecord(
            installationID: Data(repeating: marker, count: 16),
            displayName: "Pistis test installation",
            audience: "prosopikon:pistis:enrolment",
            authorisedProductAudiences: ["propylaion"],
            userID: Data(repeating: marker &+ 1, count: 16),
            externalIdentityID: Data(repeating: marker &+ 2, count: 16),
            fingerprint: Data(repeating: marker &+ 3, count: 32),
            installationKeyID: Data(repeating: marker &+ 4, count: 32),
            installationPublicKey: Data([0x02]) + Data(repeating: marker &+ 5, count: 32),
            authorityKeyID: Data(repeating: marker &+ 6, count: 32),
            authorityReceipt: Data([marker]),
            policyGeneration: 1,
            revocationGeneration: 1,
            expiresAt: Date(timeIntervalSince1970: 1_900_000_000),
            active: true
        )
        return try AuthenticatedEnrollmentOutput(
            trust: trust,
            responseContext: DeviceResponseContext(
                deviceID: Data(repeating: marker &+ 7, count: 16),
                deviceKeyID: Data(repeating: marker &+ 8, count: 32),
                userID: trust.userID,
                externalIdentityID: trust.externalIdentityID
            ),
            allowedHosts: ["pistis.example.test"],
            httpsOrigin: "https://pistis.example.test",
            tlsSPKISHA256: Data(repeating: pin, count: 32)
        )
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
