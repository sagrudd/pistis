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

    func testTaskScopedChallengeUsesThePinnedVerifier() throws {
        let delegate = try PinnedEnrolmentSessionDelegate(
            origin: try XCTUnwrap(URL(string: "https://monas.example.test")),
            expectedSPKISHA256: Data(repeating: 0x11, count: 32)
        )
        let protectionSpace = URLProtectionSpace(
            host: "monas.example.test",
            port: 443,
            protocol: "https",
            realm: nil,
            authenticationMethod: NSURLAuthenticationMethodHTTPBasic
        )
        let challenge = URLAuthenticationChallenge(
            protectionSpace: protectionSpace,
            proposedCredential: nil,
            previousFailureCount: 0,
            failureResponse: nil,
            error: nil,
            sender: nil
        )
        let task = URLSession(configuration: .ephemeral)
            .dataTask(with: URL(string: "https://monas.example.test")!)
        let expectation = expectation(description: "task challenge completed")

        delegate.urlSession(URLSession.shared, task: task, didReceive: challenge) {
            disposition, credential in
            XCTAssertEqual(disposition, .cancelAuthenticationChallenge)
            XCTAssertNil(credential)
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 1)
    }

    private func fixture() throws -> Data {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("../Fixtures/pistis-example-test.der")
            .standardizedFileURL
        return try Data(contentsOf: url)
    }
}
