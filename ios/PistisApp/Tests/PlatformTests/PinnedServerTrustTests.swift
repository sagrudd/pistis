import CryptoKit
import Foundation
import XCTest

@testable import Pistis

final class PinnedServerTrustTests: XCTestCase {
    func testExtractsExactSPKIFromClosedCertificateFixture() throws {
        let certificate = try fixture()
        let spki = try CertificateSPKI.extract(from: certificate)
        XCTAssertEqual(
            Data(SHA256.hash(data: spki)).map {
                String(format: "%02x", $0)
            }.joined(),
            "c7a5f8cbb560543b413b54496eaba3bef3c319541594a14aeb4a827146f1c832"
        )
    }

    func testLaterAuthenticationRejectsChangedCertificateSPKI() throws {
        let certificate = try fixture()
        let expected = Data(SHA256.hash(data: try CertificateSPKI.extract(from: certificate)))
        XCTAssertTrue(
            PinnedEnrolmentSessionDelegate.matchesSPKI(
                certificateDER: certificate,
                expectedSPKISHA256: expected
            )
        )
        XCTAssertFalse(
            PinnedEnrolmentSessionDelegate.matchesSPKI(
                certificateDER: certificate,
                expectedSPKISHA256: Data(repeating: 0, count: 32)
            )
        )
    }

    func testLaterAuthenticationRejectsEndpointOutsidePersistedOrigin() async throws {
        let transport = try AuthenticationResponseTransport(
            allowedHosts: ["monas.example.test"],
            httpsOrigin: "https://monas.example.test",
            tlsSPKISHA256: Data(repeating: 0x11, count: 32)
        )
        let endpoint = try XCTUnwrap(URL(string: "https://attacker.example.test/auth"))
        do {
            _ = try await transport.status(at: endpoint)
            XCTFail("endpoint outside the signed origin unexpectedly reached transport")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .invalidConfiguration)
        }
    }

    func testRejectsEveryCertificateTruncationAndNonMinimalLength() throws {
        let certificate = try fixture()
        for length in 0 ..< certificate.count {
            XCTAssertThrowsError(
                try CertificateSPKI.extract(from: certificate.prefix(length)),
                "truncation \(length) unexpectedly exposed an SPKI"
            )
        }
        var nonMinimal = Data([0x30, 0x82, 0x00, 0x7f])
        nonMinimal.append(Data(repeating: 0, count: 127))
        XCTAssertThrowsError(try CertificateSPKI.extract(from: nonMinimal))
    }

    private func fixture() throws -> Data {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("../Fixtures/pistis-example-test.der")
            .standardizedFileURL
        return try Data(contentsOf: url)
    }
}
