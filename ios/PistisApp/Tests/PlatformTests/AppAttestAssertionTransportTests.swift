import CryptoKit
import Foundation
import XCTest

@testable import Pistis

final class AppAttestAssertionTransportTests: XCTestCase {
    func testClientHashesExactPurposeSeparatedAssertionBytes() async throws {
        let keyID = Data(repeating: 0x11, count: 32).base64EncodedString()
        let service = RecordingAppAttestService(keyID: keyID)
        let client = AppleAppAttestClient(
            service: service,
            keyIDStore: FixedKeyIDStore(keyID: keyID)
        )
        let vector = try assertionVector()
        let bootstrap = try MonasAppAttestCeremonyBootstrap(
            httpsOrigin: try XCTUnwrap(URL(string: "https://monas.example.test")),
            tlsSPKISHA256: Data(repeating: 0x12, count: 32),
            ceremonyID: Data(repeating: 0x22, count: 16),
            challengeDigest: vector.challengeDigest
        )
        let envelope = try await client.prepareAssertion(bootstrap: bootstrap)

        XCTAssertEqual(
            AppleAppAttestClient.assertionClientDataPrefix + vector.challengeDigest,
            vector.clientData
        )
        XCTAssertEqual(service.assertionHash, vector.clientDataHash)
        XCTAssertEqual(
            envelope.ceremonyIDB64URL,
            Data(repeating: 0x22, count: 16).base64EncodedString()
                .replacingOccurrences(of: "=", with: "")
        )
        XCTAssertEqual(envelope.profile,
                       "mnemosyne.pistis.site-trust-app-attest-assertion-ingress.v1")
        XCTAssertFalse(envelope.assertionB64URL.contains("="))
    }

    func testAssertionEnvelopeRejectsZeroOrOversizedInputs() {
        XCTAssertThrowsError(try AppleAppAttestAssertionEnvelope(
            ceremonyID: Data(repeating: 0, count: 16), assertion: Data([1])
        ))
        XCTAssertThrowsError(try AppleAppAttestAssertionEnvelope(
            ceremonyID: Data(repeating: 1, count: 15), assertion: Data([1])
        ))
        XCTAssertThrowsError(try AppleAppAttestAssertionEnvelope(
            ceremonyID: Data(repeating: 1, count: 16),
            assertion: Data(repeating: 2, count: 16_385)
        ))
    }

    func testTransportPostsOnlyExactCanonicalAssertionEnvelope() async throws {
        AssertionURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AssertionURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            bootstrap: bootstrap(), configuration: configuration
        )
        let envelope = try AppleAppAttestAssertionEnvelope(
            ceremonyID: Data(repeating: 0x22, count: 16),
            assertion: Data(repeating: 0x44, count: 64)
        )
        try await transport.submitAssertion(envelope)

        let request = try XCTUnwrap(AssertionURLProtocol.lastRequest())
        XCTAssertEqual(request.url?.absoluteString,
                       "https://monas.example.test/v1/pistis/site-trust/app-attest/assertion")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"),
                       "application/json; charset=utf-8")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Cookie"), nil)
        let body = try XCTUnwrap(AssertionURLProtocol.lastBody())
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: body) as? [String: Any]
        )
        XCTAssertEqual(Set(object.keys), ["profile", "ceremony_id_b64url", "assertion_b64url"])
        XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
    }

    func testRegistrationUsesItsDistinctPinnedJSONEndpoint() async throws {
        AssertionURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AssertionURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            bootstrap: bootstrap(), configuration: configuration
        )
        let envelope = try AppleAppAttestRegistrationEnvelope(
            ceremonyID: "server-owned-registration-ceremony",
            siteTrustDomain: "site-trust.example",
            appleKeyID: Data(repeating: 0x11, count: 32).base64EncodedString(),
            clientDataHash: Data(repeating: 0x22, count: 32),
            attestationObject: Data(repeating: 0x33, count: 64)
        )
        try await transport.submitRegistration(envelope)
        let request = try XCTUnwrap(AssertionURLProtocol.lastRequest())
        XCTAssertEqual(request.url?.absoluteString,
                       "https://monas.example.test/v1/pistis/site-trust/app-attest/registration")
        let body = try XCTUnwrap(AssertionURLProtocol.lastBody())
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: body) as? [String: Any]
        )
        XCTAssertEqual(Set(object.keys), [
            "protocol", "ceremony_id", "site_trust_domain", "app_identifier",
            "key_id_b64url", "client_data_hash_b64url", "attestation_object_b64url",
        ])
    }

    func testCustodyRewrapUsesOnlyItsFixedPinnedSubmissionEndpoint() async throws {
        AssertionURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AssertionURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            bootstrap: bootstrap(), configuration: configuration
        )
        try await transport.submitCustodyRewrap(IphoneMediatedCustodyRewrapSubmissionV1(
            correlation: Data(repeating: 0x01, count: 16),
            canonicalPayload: Data(repeating: 0x02, count: 64),
            deviceKeyID: "site-root-1",
            delegationSerial: "serial-1",
            siteTrustDomain: "site-1",
            purpose: IphoneMediatedCustodyRewrapPurposeV1.value,
            coseSign1: Data(repeating: 0x03, count: 64),
            rewrappedCiphertext: Data(repeating: 0x04, count: 60)
        ))

        let request = try XCTUnwrap(AssertionURLProtocol.lastRequest())
        XCTAssertEqual(request.url?.absoluteString,
                       "https://monas.example.test/v1/pistis/site-trust/custody-rewrap/submit")
        XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))
        XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
        let body = try XCTUnwrap(AssertionURLProtocol.lastBody())
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(Set(object.keys), [
            "schema", "correlation_b64url", "canonical_challenge_b64url", "device_key_id",
            "delegation_serial", "site_trust_domain", "purpose", "detached_cose_sign1_b64url",
            "rewrapped_ciphertext_b64url",
        ])
    }

    func testTransportRejectsRedirectOrNonAcceptedResponse() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RejectingAssertionURLProtocol.self]
        let transport = try MonasAppAttestTransport(
            bootstrap: bootstrap(), configuration: configuration
        )
        let envelope = try AppleAppAttestAssertionEnvelope(
            ceremonyID: Data(repeating: 0x22, count: 16), assertion: Data([1])
        )
        do {
            try await transport.submitAssertion(envelope)
            XCTFail("non-202 response must not be accepted")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .productionEnvelopeUnavailable)
        }
    }

    private func bootstrap() throws -> MonasAppAttestCeremonyBootstrap {
        try MonasAppAttestCeremonyBootstrap(
            httpsOrigin: try XCTUnwrap(URL(string: "https://monas.example.test")),
            tlsSPKISHA256: Data(repeating: 0x12, count: 32),
            ceremonyID: Data(repeating: 0x22, count: 16),
            challengeDigest: Data(repeating: 0x33, count: 32)
        )
    }

    private func assertionVector() throws -> (
        challengeDigest: Data, clientData: Data, clientDataHash: Data
    ) {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("../../../../fixtures/app-attest/site-trust-assertion-client-data-v1.json")
            .standardizedFileURL
        let object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: root)) as? [String: String]
        )
        return (
            try decodeCanonicalB64URL(object["challenge_digest_b64url"]),
            try decodeCanonicalB64URL(object["client_data_b64url"]),
            try decodeCanonicalB64URL(object["client_data_sha256_b64url"])
        )
    }
}

private func decodeCanonicalB64URL(_ value: String?) throws -> Data {
    let value = try XCTUnwrap(value)
    XCTAssertFalse(value.contains("="))
    XCTAssertTrue(value.unicodeScalars.allSatisfy {
        $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_")
    })
    let padded = value.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
        + String(repeating: "=", count: (4 - value.count % 4) % 4)
    return try XCTUnwrap(Data(base64Encoded: padded))
}

private final class FixedKeyIDStore: AppleAppAttestKeyIDStoring, @unchecked Sendable {
    let keyID: String
    init(keyID: String) { self.keyID = keyID }
    func loadKeyID() -> String? { keyID }
    func saveKeyID(_: String) throws {}
}

private final class RecordingAppAttestService: AppleAppAttestServicing, @unchecked Sendable {
    let keyID: String
    private(set) var assertionHash: Data?
    init(keyID: String) { self.keyID = keyID }
    var isSupported: Bool { true }
    func generateKey() async throws -> String { keyID }
    func attestKey(_: String, clientDataHash _: Data) async throws -> Data { Data([1]) }
    func generateAssertion(_: String, clientDataHash: Data) async throws -> Data {
        assertionHash = clientDataHash
        return Data(repeating: 0x44, count: 64)
    }
}

private final class AssertionURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var requestValue: URLRequest?
    private nonisolated(unsafe) static var bodyValue: Data?

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        Self.requestValue = request
        Self.bodyValue = request.httpBody ?? readBodyStream(request.httpBodyStream)
        Self.lock.unlock()
        let response = HTTPURLResponse(
            url: request.url!, statusCode: 202, httpVersion: "HTTP/1.1",
            headerFields: ["Cache-Control": "no-store"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    static func lastRequest() -> URLRequest? {
        lock.lock(); defer { lock.unlock() }
        return requestValue
    }

    static func lastBody() -> Data? {
        lock.lock(); defer { lock.unlock() }
        return bodyValue
    }

    static func reset() {
        lock.lock(); defer { lock.unlock() }
        requestValue = nil
        bodyValue = nil
    }
}

private final class RejectingAssertionURLProtocol: URLProtocol, @unchecked Sendable {
    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let response = HTTPURLResponse(
            url: request.url!, statusCode: 302, httpVersion: "HTTP/1.1",
            headerFields: ["Location": "https://redirect.invalid/"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private func readBodyStream(_ stream: InputStream?) -> Data {
    guard let stream else { return Data() }
    stream.open()
    defer { stream.close() }
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 4_096)
    while stream.hasBytesAvailable {
        let count = stream.read(&buffer, maxLength: buffer.count)
        guard count > 0 else { break }
        data.append(buffer, count: count)
    }
    return data
}
