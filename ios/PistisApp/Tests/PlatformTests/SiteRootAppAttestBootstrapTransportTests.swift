import Foundation
import XCTest

@testable import Pistis

final class SiteRootAppAttestBootstrapTransportTests: XCTestCase {
    override func tearDown() {
        BootstrapURLProtocol.reset()
        super.tearDown()
    }

    func testSignedSiteRootSuccessDecodesOnlyExactBootstrapAndPinsAssertionTransport() async throws {
        let response = responseJSON(
            origin: "https://monas.example.test",
            spki: Data(repeating: 0x11, count: 32),
            ceremonyID: Data(repeating: 0x22, count: 16),
            challenge: Data(repeating: 0x33, count: 32),
            expiresAt: nowMillis() + 60_000
        )
        BootstrapURLProtocol.configure(response: response, status: 200)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BootstrapURLProtocol.self]
        let transport = try MonasSiteRootDelegationTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test")),
            expectedSPKISHA256: Data(repeating: 0x11, count: 32),
            configuration: configuration
        )

        let bootstrap = try await transport.submit(submissionRequest())

        XCTAssertEqual(bootstrap.httpsOrigin.absoluteString, "https://monas.example.test")
        XCTAssertEqual(bootstrap.tlsSPKISHA256, Data(repeating: 0x11, count: 32))
        XCTAssertEqual(bootstrap.ceremonyID, Data(repeating: 0x22, count: 16))
        XCTAssertEqual(bootstrap.challengeDigest, Data(repeating: 0x33, count: 32))

        let assertionTransport = try MonasAppAttestTransport(
            bootstrap: bootstrap,
            configuration: configuration
        )
        let assertion = try AppleAppAttestAssertionEnvelope(
            ceremonyID: bootstrap.ceremonyID,
            assertion: Data(repeating: 0x44, count: 64)
        )
        try await assertionTransport.submitAssertion(assertion)

        let requests = BootstrapURLProtocol.requests()
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(
            requests[0].url?.path,
            MonasSiteRootDelegationEndpointV1.submitPath
        )
        XCTAssertEqual(
            requests[1].url?.absoluteString,
            "https://monas.example.test/v1/pistis/site-trust/app-attest/assertion"
        )
        XCTAssertNil(requests[0].value(forHTTPHeaderField: "Cookie"))
        XCTAssertNil(requests[0].value(forHTTPHeaderField: "Authorization"))
        XCTAssertNil(requests[1].value(forHTTPHeaderField: "Cookie"))
        XCTAssertNil(requests[1].value(forHTTPHeaderField: "Authorization"))
    }

    func testCoarseReceiptAndExtendedBootstrapAreTerminal() async throws {
        let receipt = """
        {"schema":"monas.site-root-delegation-submission-receipt.v1","reference":"opaque","state":"completed"}
        """.data(using: .utf8)!
        try await assertSubmissionDenied(response: receipt)

        let extended = responseJSON(
            origin: "https://monas.example.test",
            spki: Data(repeating: 0x11, count: 32),
            ceremonyID: Data(repeating: 0x22, count: 16),
            challenge: Data(repeating: 0x33, count: 32),
            expiresAt: nowMillis() + 60_000,
            additionalField: ",\"session\":\"forbidden\""
        )
        try await assertSubmissionDenied(response: extended)
    }

    func testAuthorityCustodyStatusUsesOnlyFixedNoStoreState() async throws {
        let response = Data(
            #"{"schema":"monas.first-authority-custody-status.v2","state":"recovery-required"}"#.utf8
        )
        BootstrapURLProtocol.configure(response: response, status: 200)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BootstrapURLProtocol.self]
        let transport = try MonasSiteRootDelegationTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test")),
            expectedSPKISHA256: Data(repeating: 0x11, count: 32),
            configuration: configuration
        )
        let status = try await transport.authorityCustodyStatusV2()
        XCTAssertEqual(status, .recoveryRequired)
        let request = try XCTUnwrap(BootstrapURLProtocol.requests().first)
        XCTAssertEqual(
            request.url?.path, "/v1/pistis/site-trust/authority-custody/v2/status"
        )
        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))
        XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))

        BootstrapURLProtocol.configure(
            response: Data(
                #"{"schema":"monas.first-authority-custody-status.v2","state":"unknown"}"#.utf8
            ), status: 200
        )
        do {
            _ = try await transport.authorityCustodyStatusV2()
            XCTFail("unknown custody status unexpectedly selected a mode")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .siteRootAuthorityUnavailable)
        }
    }

    func testAuthorityCustodyStatusTreatsEmptyNoStore503AsAssertionRequired() async throws {
        BootstrapURLProtocol.configure(response: Data(), status: 503)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BootstrapURLProtocol.self]
        let transport = try MonasSiteRootDelegationTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test")),
            expectedSPKISHA256: Data(repeating: 0x11, count: 32),
            configuration: configuration
        )

        let status = try await transport.authorityCustodyStatusV2()
        XCTAssertEqual(status, .appAttestAssertionRequired)
    }

    func testAuthorityCustodyStatusRejects503WithBody() async throws {
        BootstrapURLProtocol.configure(response: Data("unexpected".utf8), status: 503)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BootstrapURLProtocol.self]
        let transport = try MonasSiteRootDelegationTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test")),
            expectedSPKISHA256: Data(repeating: 0x11, count: 32),
            configuration: configuration
        )

        do {
            _ = try await transport.authorityCustodyStatusV2()
            XCTFail("non-empty unavailable response selected an assertion state")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .siteRootAuthorityUnavailable)
        }
    }

    func testInitialStaticCeremonyAcceptsOnlyAnEmpty204Completion() async throws {
        BootstrapURLProtocol.configure(response: Data(), status: 204)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BootstrapURLProtocol.self]
        let transport = try MonasSiteRootDelegationTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test")),
            expectedSPKISHA256: Data(repeating: 0x11, count: 32),
            configuration: configuration
        )

        try await transport.submitInitialStaticCompletion(submissionRequest())

        let requests = BootstrapURLProtocol.requests()
        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(requests[0].url?.path, MonasSiteRootDelegationEndpointV1.submitPath)
        XCTAssertNil(requests[0].value(forHTTPHeaderField: "Cookie"))
        XCTAssertNil(requests[0].value(forHTTPHeaderField: "Authorization"))
    }

    func testInitialStaticCeremonyRejectsBootstrapAndNonempty204() async throws {
        try await assertInitialStaticCompletionDenied(
            response: responseJSON(
                origin: "https://monas.example.test",
                spki: Data(repeating: 0x11, count: 32),
                ceremonyID: Data(repeating: 0x22, count: 16),
                challenge: Data(repeating: 0x33, count: 32),
                expiresAt: nowMillis() + 60_000
            ),
            status: 200
        )
        try await assertInitialStaticCompletionDenied(
            response: Data("unexpected".utf8),
            status: 204
        )
    }

    func testAlternateOriginNoncanonicalOrExpiredBootstrapIsTerminal() async throws {
        let alternateOrigin = responseJSON(
            origin: "https://other.example.test",
            spki: Data(repeating: 0x11, count: 32),
            ceremonyID: Data(repeating: 0x22, count: 16),
            challenge: Data(repeating: 0x33, count: 32),
            expiresAt: nowMillis() + 60_000
        )
        try await assertSubmissionDenied(response: alternateOrigin)

        let noncanonicalPin = responseJSON(
            origin: "https://monas.example.test",
            spki: Data(repeating: 0x11, count: 32),
            ceremonyID: Data(repeating: 0x22, count: 16),
            challenge: Data(repeating: 0x33, count: 32),
            expiresAt: nowMillis() + 60_000,
            pinSuffix: "="
        )
        try await assertSubmissionDenied(response: noncanonicalPin)

        let expired = responseJSON(
            origin: "https://monas.example.test",
            spki: Data(repeating: 0x11, count: 32),
            ceremonyID: Data(repeating: 0x22, count: 16),
            challenge: Data(repeating: 0x33, count: 32),
            expiresAt: nowMillis() - 1
        )
        try await assertSubmissionDenied(response: expired)
    }

    private func assertSubmissionDenied(response: Data) async throws {
        BootstrapURLProtocol.configure(response: response, status: 200)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BootstrapURLProtocol.self]
        let transport = try MonasSiteRootDelegationTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test")),
            expectedSPKISHA256: Data(repeating: 0x11, count: 32),
            configuration: configuration
        )
        do {
            _ = try await transport.submit(submissionRequest())
            XCTFail("only the exact bootstrap response may be accepted")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .siteRootAuthorityUnavailable)
        }
    }

    private func assertInitialStaticCompletionDenied(response: Data, status: Int) async throws {
        BootstrapURLProtocol.configure(response: response, status: status)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BootstrapURLProtocol.self]
        let transport = try MonasSiteRootDelegationTransport(
            authorityOrigin: try XCTUnwrap(URL(string: "https://monas.example.test")),
            expectedSPKISHA256: Data(repeating: 0x11, count: 32),
            configuration: configuration
        )
        do {
            try await transport.submitInitialStaticCompletion(submissionRequest())
            XCTFail("only an empty static completion may be accepted")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .siteRootAuthorityUnavailable)
        }
    }

    private func submissionRequest() throws -> MonasSiteRootDelegationSubmissionRequestV1 {
        let endpoint = try XCTUnwrap(URL(string:
            "https://monas.example.test/auth/pistis/site-root-delegations/v1/submit"
        ))
        return .init(
            endpoint: endpoint,
            submission: .init(
                schema: SiteRootDelegationSubmissionV1.schema,
                reference: "opaque-reference",
                canonicalDelegationJSON: Data("{}".utf8),
                coseSign1: Data([0x84])
            )
        )
    }

    private func responseJSON(
        origin: String,
        spki: Data,
        ceremonyID: Data,
        challenge: Data,
        expiresAt: UInt64,
        pinSuffix: String = "",
        additionalField: String = ""
    ) -> Data {
        let encode: (Data) -> String = { value in
            value.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let body = "{\"schema\":\"monas.pistis.site-trust-app-attest-bootstrap.v1\","
            + "\"https_origin\":\"\(origin)\","
            + "\"tls_spki_sha256_b64url\":\"\(encode(spki))\(pinSuffix)\","
            + "\"ceremony_id_b64url\":\"\(encode(ceremonyID))\","
            + "\"challenge_digest_b64url\":\"\(encode(challenge))\","
            + "\"expires_at_unix_millis\":\(expiresAt)"
            + additionalField
            + "}"
        return Data(body.utf8)
    }

    private func nowMillis() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1_000)
    }
}

private final class BootstrapURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var responseData = Data()
    private nonisolated(unsafe) static var statusCode = 503
    private nonisolated(unsafe) static var receivedRequests = [URLRequest]()

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        Self.receivedRequests.append(request)
        let data = Self.responseData
        let configuredStatus = Self.statusCode
        Self.lock.unlock()

        let assertion = request.url?.path == "/v1/pistis/site-trust/app-attest/assertion"
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: assertion ? 202 : configuredStatus,
            httpVersion: "HTTP/1.1",
            headerFields: ["Cache-Control": "no-store"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if !assertion {
            client?.urlProtocol(self, didLoad: data)
        }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    static func configure(response: Data, status: Int) {
        lock.lock(); defer { lock.unlock() }
        responseData = response
        statusCode = status
        receivedRequests = []
    }

    static func requests() -> [URLRequest] {
        lock.lock(); defer { lock.unlock() }
        return receivedRequests
    }

    static func reset() {
        lock.lock(); defer { lock.unlock() }
        responseData = Data()
        statusCode = 503
        receivedRequests = []
    }
}
