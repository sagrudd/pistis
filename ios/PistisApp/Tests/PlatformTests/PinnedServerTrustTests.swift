import CryptoKit
import Foundation
import Security
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

    func testSiteRootTrustAcceptsRotatedLeafWithoutPinOrReenrolment() throws {
        let rootDER = try fixture(named: "site-root-generation-7")
        let policy = try MonasServerTrustPolicy(
            siteRootDER: rootDER,
            fingerprintSHA256: Data(SHA256.hash(data: rootDER)),
            generation: 7
        )
        let firstLeaf = try fixture(named: "site-leaf-generation-7-a")
        let rotatedLeaf = try fixture(named: "site-leaf-generation-7-b")
        let firstSPKI = Data(SHA256.hash(data: try CertificateSPKI.extract(from: firstLeaf)))
        let rotatedSPKI = Data(SHA256.hash(data: try CertificateSPKI.extract(from: rotatedLeaf)))
        XCTAssertNotEqual(firstSPKI, rotatedSPKI)

        let firstTrust = try trust(
            for: "site-leaf-generation-7-a",
            issuer: "site-root-generation-7"
        )
        let rotatedTrust = try trust(
            for: "site-leaf-generation-7-b",
            issuer: "site-root-generation-7"
        )
        XCTAssertTrue(
            PinnedEnrolmentSessionDelegate.acceptsServerTrust(
                firstTrust,
                host: "monas.example.test",
                trustPolicy: policy
            ),
            "first-leaf trust result: \(String(describing: SecTrustCopyResult(firstTrust)))"
        )
        XCTAssertTrue(
            PinnedEnrolmentSessionDelegate.acceptsServerTrust(
                rotatedTrust,
                host: "monas.example.test",
                trustPolicy: policy
            ),
            "rotated-leaf trust result: \(String(describing: SecTrustCopyResult(rotatedTrust)))"
        )
    }

    func testSiteRootTrustRejectsDifferentRootGenerationAndHostname() throws {
        let rootDER = try fixture(named: "site-root-generation-7")
        let policy = try MonasServerTrustPolicy(
            siteRootDER: rootDER,
            fingerprintSHA256: Data(SHA256.hash(data: rootDER)),
            generation: 7
        )

        XCTAssertFalse(
            PinnedEnrolmentSessionDelegate.acceptsServerTrust(
                try trust(for: "site-leaf-generation-8", issuer: "site-root-generation-8"),
                host: "monas.example.test",
                trustPolicy: policy
            ),
            "a leaf issued by the replacement root must not pass the retained generation"
        )
        XCTAssertFalse(
            PinnedEnrolmentSessionDelegate.acceptsServerTrust(
                try trust(for: "site-leaf-wrong-host", issuer: "site-root-generation-7"),
                host: "monas.example.test",
                trustPolicy: policy
            ),
            "the retained root does not override TLS hostname validation"
        )
    }

    func testSiteRootTrustRejectsExpiredLeaf() throws {
        let rootDER = try fixture(named: "site-root-generation-7")
        let policy = try MonasServerTrustPolicy(
            siteRootDER: rootDER,
            fingerprintSHA256: Data(SHA256.hash(data: rootDER)),
            generation: 7
        )
        let expiredAt = try XCTUnwrap(
            ISO8601DateFormatter().date(from: "2040-01-01T00:00:00Z")
        )
        XCTAssertFalse(
            PinnedEnrolmentSessionDelegate.acceptsServerTrust(
                try trust(
                    for: "site-leaf-generation-7-a",
                    issuer: "site-root-generation-7",
                    verifyDate: expiredAt
                ),
                host: "monas.example.test",
                trustPolicy: policy
            )
        )
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
        try fixture(named: "pistis-example-test")
    }

    private func fixture(named name: String) throws -> Data {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("../Fixtures/\(name).der")
            .standardizedFileURL
        return try Data(contentsOf: url)
    }

    private func trust(
        for certificateName: String,
        issuer issuerName: String? = nil,
        verifyDate: Date? = nil
    ) throws -> SecTrust {
        let certificate = try XCTUnwrap(
            SecCertificateCreateWithData(
                nil,
                try fixture(named: certificateName) as CFData
            )
        )
        let chain: [SecCertificate]
        if let issuerName {
            let issuer = try XCTUnwrap(
                SecCertificateCreateWithData(
                    nil,
                    try fixture(named: issuerName) as CFData
                )
            )
            chain = [certificate, issuer]
        } else {
            chain = [certificate]
        }
        var createdTrust: SecTrust?
        XCTAssertEqual(
            SecTrustCreateWithCertificates(
                chain as CFArray,
                SecPolicyCreateBasicX509(),
                &createdTrust
            ),
            errSecSuccess
        )
        let trust = try XCTUnwrap(createdTrust)
        XCTAssertEqual(SecTrustSetNetworkFetchAllowed(trust, false), errSecSuccess)
        if let verifyDate {
            XCTAssertEqual(SecTrustSetVerifyDate(trust, verifyDate as CFDate), errSecSuccess)
        }
        return trust
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
