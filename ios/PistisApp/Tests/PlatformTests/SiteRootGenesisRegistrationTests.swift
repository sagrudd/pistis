import Foundation
import XCTest

@testable import Pistis

final class SiteRootGenesisRegistrationTests: XCTestCase {
    private let origin = URL(string: "https://monas.example.test")!
    private let now: UInt64 = 1_700_000_000_000

    func testGenesisPresentationAcceptsOnlyFixedAuthorityAndExactNonceBinding() throws {
        let presentation = try SiteRootGenesisRegistrationPresentationV1(
            qrText: genesisQR(),
            authorityOrigin: origin,
            nowUnixMillis: now
        )
        XCTAssertEqual(presentation.reference, "genesis-reference-1")
        XCTAssertEqual(presentation.siteTrustDomain, "site-demo-1")
        XCTAssertEqual(
            presentation.registrationURL.path,
            MonasSiteRootGenesisEndpointV1.registrationPath
        )
        XCTAssertEqual(presentation.appAttestChallengeDigest, Data(repeating: 0x22, count: 32))

        XCTAssertThrowsError(try SiteRootGenesisRegistrationPresentationV1(
            qrText: genesisQR(registrationURL: "https://other.example.test/auth/pistis/site-root-genesis/v1/register"),
            authorityOrigin: origin,
            nowUnixMillis: now
        ))
        XCTAssertThrowsError(try SiteRootGenesisRegistrationPresentationV1(
            qrText: genesisQR(expiry: now + 300_001),
            authorityOrigin: origin,
            nowUnixMillis: now
        ))
        XCTAssertThrowsError(try SiteRootGenesisRegistrationPresentationV1(
            qrText: genesisQR(extra: ",\"endpoint\":\"https://other.example.test\""),
            authorityOrigin: origin,
            nowUnixMillis: now
        ))
    }

    func testGenesisResultMustBindTheReturnedDelegationToTheSubmittedPublicKey() throws {
        let request = try request()
        let canonical = canonicalDelegation(deviceKeyID: request.siteRootKey.deviceKeyID)
        let result = try MonasSiteRootGenesisRegistrationResult(
            data: resultJSON(
                canonical: canonical,
                deviceKeyID: request.siteRootKey.deviceKeyID,
                reference: request.presentation.reference
            ),
            request: request,
            authorityOrigin: origin
        )
        XCTAssertEqual(result.presentation.deviceKeyID, request.siteRootKey.deviceKeyID)
        XCTAssertEqual(result.presentation.canonicalDelegationJSON, canonical)

        XCTAssertThrowsError(try MonasSiteRootGenesisRegistrationResult(
            data: resultJSON(
                canonical: canonical,
                deviceKeyID: "site-root-other",
                reference: request.presentation.reference
            ),
            request: request,
            authorityOrigin: origin
        ))
    }

    func testGenesisRequestContainsOnlyTypedPublicRegistrationAndExistingAppAttestEnvelope() throws {
        let request = try request()
        let encoded = try JSONEncoder().encode(MonasSiteRootGenesisRegistrationRequest(request))
        let object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        XCTAssertEqual(Set(object.keys), ["schema", "reference", "site_root_key", "app_attest_registration"])
        XCTAssertEqual(object["schema"] as? String, "monas.site-root-genesis-registration.v1")
        XCTAssertNil(object["token"])
        XCTAssertNil(object["cookie"])
        XCTAssertNil(object["private_key"])
        let key = try XCTUnwrap(object["site_root_key"] as? [String: Any])
        XCTAssertEqual(key["device_key_id"] as? String, request.siteRootKey.deviceKeyID)
        XCTAssertEqual(key["secure_enclave_attestation"] as? String, "not-asserted")
    }

    func testBrokerGenesisRequiresOpaqueCorrelationAndFixedInstallOrigin() throws {
        let brokerOrigin = URL(string: MonasSiteRootGenesisBrokerEndpointV1.origin)!
        let presentation = try SiteRootGenesisRegistrationPresentationV1(
            qrText: brokerQR(),
            authorityOrigins: [brokerOrigin],
            nowUnixMillis: now,
            requireCorrelation: true
        )
        XCTAssertEqual(presentation.correlation, Data(repeating: 0x44, count: 32))
        XCTAssertEqual(presentation.registrationURL.host, "install.mnemosyne.co.uk")

        XCTAssertThrowsError(try SiteRootGenesisRegistrationPresentationV1(
            qrText: brokerQR(registrationURL: "https://customer.example.test/register"),
            authorityOrigins: [brokerOrigin],
            nowUnixMillis: now,
            requireCorrelation: true
        ))
        XCTAssertThrowsError(try SiteRootGenesisRegistrationPresentationV1(
            qrText: brokerQR(correlation: nil),
            authorityOrigins: [brokerOrigin],
            nowUnixMillis: now,
            requireCorrelation: true
        ))
    }

    func testBrokerGenesisRelaysRegistrationResultAndStaticProof() async throws {
        GenesisBrokerURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [GenesisBrokerURLProtocol.self]
        let transport = try MonasSiteRootGenesisBrokerTransport(
            session: URLSession(configuration: configuration)
        )
        let request = try brokerRequest()

        let delegation = try await transport.registerGenesis(request)
        let correlation = try XCTUnwrap(delegation.correlation)
        XCTAssertEqual(correlation, Data(repeating: 0x44, count: 32))
        XCTAssertEqual(
            delegation.submitURL.absoluteString,
            MonasSiteRootGenesisBrokerEndpointV1.origin
                + MonasSiteRootGenesisBrokerEndpointV1.proofPath
        )
        let submission = SiteRootDelegationSubmissionV1(
            schema: SiteRootDelegationSubmissionV1.schema,
            reference: delegation.reference,
            canonicalDelegationJSON: delegation.canonicalDelegationJSON,
            coseSign1: Data([0x01, 0x02]),
            correlation: correlation
        )
        try await transport.submitInitialStaticCompletion(
            MonasSiteRootDelegationSubmissionRequestV1(
                endpoint: delegation.submitURL,
                submission: submission
            )
        )

        let requests = GenesisBrokerURLProtocol.requests()
        XCTAssertEqual(
            requests.map { $0.url?.path },
            [
                MonasSiteRootGenesisBrokerEndpointV1.registrationPath,
                MonasSiteRootGenesisBrokerEndpointV1.delegationPollPath,
                MonasSiteRootGenesisBrokerEndpointV1.proofPath,
            ]
        )
        for request in requests {
            XCTAssertEqual(request.url?.host, "install.mnemosyne.co.uk")
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Cache-Control"), "no-store")
        }
        let registration = try XCTUnwrap(jsonObject(requests[0]))
        XCTAssertEqual(
            Set(registration.keys),
            [
                "schema", "purpose", "reference", "correlation_b64url",
                "registration_request_b64url",
            ]
        )
        XCTAssertEqual(
            registration["schema"] as? String,
            MonasSiteRootGenesisBrokerEndpointV1.registrationSchema
        )
        XCTAssertEqual(registration["reference"] as? String, request.presentation.reference)
        XCTAssertEqual(registration["purpose"] as? String, MonasSiteRootGenesisBrokerEndpointV1.purpose)
        XCTAssertEqual(registration["correlation_b64url"] as? String, base64URL(correlation))
        let nestedRegistration = try XCTUnwrap(
            jsonObject(try XCTUnwrap(decodeBase64URL(
                try XCTUnwrap(registration["registration_request_b64url"] as? String)
            )))
        )
        XCTAssertEqual(
            Set(nestedRegistration.keys),
            ["schema", "reference", "site_root_key", "app_attest_registration"]
        )
        let poll = try XCTUnwrap(jsonObject(requests[1]))
        XCTAssertEqual(Set(poll.keys), ["schema", "purpose", "correlation_b64url"])
        XCTAssertEqual(poll["schema"] as? String, MonasSiteRootGenesisBrokerEndpointV1.delegationPollSchema)
        XCTAssertEqual(poll["purpose"] as? String, MonasSiteRootGenesisBrokerEndpointV1.purpose)
        XCTAssertEqual(poll["correlation_b64url"] as? String, base64URL(correlation))

        let proof = try XCTUnwrap(jsonObject(requests[2]))
        XCTAssertEqual(
            Set(proof.keys),
            [
                "schema", "purpose", "correlation_b64url", "proof_b64url",
            ]
        )
        XCTAssertEqual(proof["schema"] as? String, MonasSiteRootGenesisBrokerEndpointV1.proofSchema)
        XCTAssertEqual(proof["purpose"] as? String, MonasSiteRootGenesisBrokerEndpointV1.purpose)
        XCTAssertEqual(proof["correlation_b64url"] as? String, base64URL(correlation))
        let nestedProof = try XCTUnwrap(
            jsonObject(try XCTUnwrap(decodeBase64URL(
                try XCTUnwrap(proof["proof_b64url"] as? String)
            )))
        )
        XCTAssertEqual(Set(nestedProof.keys), ["schema", "reference", "delegation", "cose_sign1_base64url"])
        XCTAssertEqual(nestedProof["reference"] as? String, delegation.reference)
    }

    private func request() throws -> SiteRootGenesisRegistrationRequestV1 {
        let presentation = try SiteRootGenesisRegistrationPresentationV1(
            qrText: genesisQR(), authorityOrigin: origin, nowUnixMillis: now
        )
        let siteRootKey = SiteRootKeyRegistrationV1(
            schema: SiteRootKeyRegistrationV1.schema,
            deviceKeyID: "site-root-1234",
            publicKeyCompressedSEC1: Data([0x02] + Array(repeating: 0x11, count: 32)),
            secureEnclaveAttestation: "not-asserted"
        )
        let appAttestRegistration = try AppleAppAttestRegistrationEnvelope(
            ceremonyID: presentation.appAttestCeremonyIDB64URL,
            siteTrustDomain: presentation.siteTrustDomain,
            appleKeyID: Data(repeating: 0x33, count: 32).base64EncodedString(),
            clientDataHash: presentation.appAttestChallengeDigest,
            attestationObject: Data(repeating: 0x44, count: 128)
        )
        return SiteRootGenesisRegistrationRequestV1(
            presentation: presentation,
            siteRootKey: siteRootKey,
            appAttestRegistration: appAttestRegistration
        )
    }

    private func brokerRequest() throws -> SiteRootGenesisRegistrationRequestV1 {
        let presentation = try SiteRootGenesisRegistrationPresentationV1(
            qrText: brokerQR(),
            authorityOrigins: [URL(string: MonasSiteRootGenesisBrokerEndpointV1.origin)!],
            nowUnixMillis: now,
            requireCorrelation: true
        )
        let siteRootKey = SiteRootKeyRegistrationV1(
            schema: SiteRootKeyRegistrationV1.schema,
            deviceKeyID: "site-root-1234",
            publicKeyCompressedSEC1: Data([0x02] + Array(repeating: 0x11, count: 32)),
            secureEnclaveAttestation: "not-asserted"
        )
        let appAttestRegistration = try AppleAppAttestRegistrationEnvelope(
            ceremonyID: presentation.appAttestCeremonyIDB64URL,
            siteTrustDomain: presentation.siteTrustDomain,
            appleKeyID: Data(repeating: 0x33, count: 32).base64EncodedString(),
            clientDataHash: presentation.appAttestChallengeDigest,
            attestationObject: Data(repeating: 0x44, count: 128)
        )
        return SiteRootGenesisRegistrationRequestV1(
            presentation: presentation,
            siteRootKey: siteRootKey,
            appAttestRegistration: appAttestRegistration
        )
    }

    private func canonicalDelegation(deviceKeyID: String) -> Data {
        Data("{\"device_key_id\":\"\(deviceKeyID)\",\"proof_profile\":\"pistis-secure-enclave-es256-cose-v1\",\"schema\":\"monas.site-root-delegation.v1\",\"secure_enclave_attestation\":\"not-asserted\",\"site_trust_domain\":\"site-demo-1\"}".utf8)
    }

    private func genesisQR(
        registrationURL: String = "https://monas.example.test/auth/pistis/site-root-genesis/v1/register",
        expiry: UInt64? = nil,
        extra: String = ""
    ) -> String {
        "{\"schema\":\"monas.site-root-genesis-registration-presentation.v1\",\"reference\":\"genesis-reference-1\",\"site_trust_domain\":\"site-demo-1\",\"registration_url\":\"\(registrationURL)\",\"app_attest_ceremony_id_b64url\":\"\(base64URL(Data(repeating: 0x11, count: 16)))\",\"app_attest_challenge_digest_b64url\":\"\(base64URL(Data(repeating: 0x22, count: 32)))\",\"expires_at_unix_millis\":\(expiry ?? now + 60_000)\(extra)}"
    }

    private func resultJSON(canonical: Data, deviceKeyID: String, reference: String) -> Data {
        Data("{\"schema\":\"monas.site-root-genesis-registration-result.v1\",\"canonical_delegation_base64url\":\"\(base64URL(canonical))\",\"device_key_id\":\"\(deviceKeyID)\",\"site_trust_domain\":\"site-demo-1\",\"submit_url\":\"https://monas.example.test/auth/pistis/site-root-delegations/v1/submit\",\"reference\":\"\(reference)\"}".utf8)
    }

    private func brokerQR(
        registrationURL: String = MonasSiteRootGenesisBrokerEndpointV1.origin
            + MonasSiteRootGenesisBrokerEndpointV1.registrationPath,
        correlation: Data? = Data(repeating: 0x44, count: 32)
    ) -> String {
        let correlationField = correlation.map {
            ",\"correlation_b64url\":\"\(base64URL($0))\""
        } ?? ""
        return "{\"schema\":\"monas.site-root-genesis-registration-presentation.v1\",\"reference\":\"genesis-reference-1\",\"site_trust_domain\":\"site-demo-1\",\"registration_url\":\"\(registrationURL)\",\"app_attest_ceremony_id_b64url\":\"\(base64URL(Data(repeating: 0x11, count: 16)))\",\"app_attest_challenge_digest_b64url\":\"\(base64URL(Data(repeating: 0x22, count: 32)))\"\(correlationField),\"expires_at_unix_millis\":\(now + 60_000)}"
    }

    private func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func jsonObject(_ request: URLRequest) throws -> [String: Any] {
        let body = try XCTUnwrap(request.httpBody ?? request.httpBodyStream.flatMap(Self.read))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
    }

    private func jsonObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func decodeBase64URL(_ value: String) -> Data? {
        guard value.utf8.allSatisfy({
            ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95
        }) else { return nil }
        let padding = String(repeating: "=", count: (4 - value.count % 4) % 4)
        return Data(base64Encoded: value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + padding)
    }

    private static func read(_ stream: InputStream) -> Data? {
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            guard count >= 0 else { return nil }
            if count == 0 { break }
            data.append(contentsOf: buffer[0..<count])
        }
        return data
    }
}

private final class GenesisBrokerURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var capturedRequests: [URLRequest] = []

    static func reset() {
        lock.lock()
        capturedRequests = []
        lock.unlock()
    }

    static func requests() -> [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return capturedRequests
    }

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host == "install.mnemosyne.co.uk"
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url else { return }
        Self.lock.lock()
        var captured = request
        captured.httpBody = request.httpBody ?? request.httpBodyStream.flatMap(Self.read)
        Self.capturedRequests.append(captured)
        Self.lock.unlock()

        let body: Data
        let status: Int
        if url.path == MonasSiteRootGenesisBrokerEndpointV1.registrationPath {
            body = Data("{\"schema\":\"\(MonasSiteRootGenesisBrokerEndpointV1.responseSchema)\",\"state\":\"accepted\"}".utf8)
            status = 202
        } else if url.path == MonasSiteRootGenesisBrokerEndpointV1.delegationPollPath {
            let canonical = "{\"device_key_id\":\"site-root-1234\",\"proof_profile\":\"pistis-secure-enclave-es256-cose-v1\",\"schema\":\"monas.site-root-delegation.v1\",\"secure_enclave_attestation\":\"not-asserted\",\"site_trust_domain\":\"site-demo-1\"}"
            let result = "{\"schema\":\"monas.site-root-genesis-registration-result.v1\",\"canonical_delegation_base64url\":\"\(Self.base64URL(Data(canonical.utf8)))\",\"device_key_id\":\"site-root-1234\",\"site_trust_domain\":\"site-demo-1\",\"submit_url\":\"https://customer.example.test/auth/pistis/site-root-delegations/v1/submit\",\"reference\":\"genesis-reference-1\"}"
            body = Data("{\"schema\":\"\(MonasSiteRootGenesisBrokerEndpointV1.responseSchema)\",\"state\":\"ready\",\"delegation_b64url\":\"\(Self.base64URL(Data(result.utf8)))\"}".utf8)
            status = 200
        } else if url.path == MonasSiteRootGenesisBrokerEndpointV1.proofPath {
            body = Data("{\"schema\":\"\(MonasSiteRootGenesisBrokerEndpointV1.responseSchema)\",\"state\":\"accepted\"}".utf8)
            status = 202
        } else {
            body = Data("{}".utf8)
            status = 404
        }
        let response = HTTPURLResponse(
            url: url,
            statusCode: status,
            httpVersion: nil,
            headerFields: ["Cache-Control": "no-store", "Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func read(_ stream: InputStream) -> Data? {
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            guard count >= 0 else { return nil }
            if count == 0 { break }
            data.append(contentsOf: buffer[0..<count])
        }
        return data
    }

    private static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
