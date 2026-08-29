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

    func testNormalLoginTransportClassifiesAuthorityRejection() async throws {
        AuthenticationURLProtocol.configure(status: 401, response: Data())
        let transport = try authenticationTransport()
        do {
            _ = try await transport.submit(
                envelope: Data([0x84, 0x01]),
                to: try XCTUnwrap(
                    URL(string: "https://192.168.0.193:8443/auth/pistis/v2/submit")
                )
            )
            XCTFail("authority rejection unexpectedly completed")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .authenticationResponseRejected)
        }
    }

    func testNormalLoginTransportClassifiesMalformedAuthorityResult() async throws {
        AuthenticationURLProtocol.configure(
            status: 200,
            response: Data(#"{"state":"accepted","evidence_id":null}"#.utf8)
        )
        let transport = try authenticationTransport()
        do {
            _ = try await transport.submit(
                envelope: Data([0x84, 0x01]),
                to: try XCTUnwrap(
                    URL(string: "https://192.168.0.193:8443/auth/pistis/v2/submit")
                )
            )
            XCTFail("malformed authority result unexpectedly completed")
        } catch {
            XCTAssertEqual(
                error as? PlatformFailure,
                .authenticationAuthorityResponseInvalid
            )
        }
    }

    func testNormalLoginTransportAcceptsExactCompletedAuthorityResult() async throws {
        AuthenticationURLProtocol.configure(
            status: 200,
            response: Data(#"{"state":"completed","evidence_id":null}"#.utf8)
        )
        let status = try await authenticationTransport().submit(
            envelope: Data([0x84, 0x01]),
            to: try XCTUnwrap(
                URL(string: "https://192.168.0.193:8443/auth/pistis/v2/submit")
            )
        )
        XCTAssertEqual(status.state, .completed)
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

    private func authenticationTransport() throws -> AuthenticationResponseTransport {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AuthenticationURLProtocol.self]
        return try AuthenticationResponseTransport(
            allowedHosts: ["192.168.0.193"],
            httpsOrigin: "https://192.168.0.193:8443",
            tlsSPKISHA256: Data(repeating: 0x11, count: 32),
            configuration: configuration
        )
    }
}

private final class AuthenticationURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var statusCode = 503
    private nonisolated(unsafe) static var responseData = Data()

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        let status = Self.statusCode
        let data = Self.responseData
        Self.lock.unlock()
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    static func configure(status: Int, response: Data) {
        lock.lock()
        defer { lock.unlock() }
        statusCode = status
        responseData = response
    }
}
