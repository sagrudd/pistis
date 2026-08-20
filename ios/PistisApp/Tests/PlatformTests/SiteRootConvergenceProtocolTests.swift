import Foundation
import CryptoKit
import XCTest
@testable import Pistis

final class SiteRootConvergenceProtocolTests: XCTestCase {
    private let nowSeconds: UInt64 = 1_900_000_000

    func testBundleReceiptPresentationBindsExactPurposeSiteGenerationAndDevice() throws {
        let challenge = provisionChallenge(site: "site-demo", generation: 7)
        let qr = json([
            "schema": SiteRootConvergenceProfileV2.provisionSchema,
            "purpose": SiteRootConvergenceProfileV2.provisionPurpose,
            "correlation_b64url": b64(Data(repeating: 1, count: 16)),
            "canonical_challenge_b64url": b64(challenge),
            "site_trust_domain": "site-demo",
            "receipt_key_generation": 7,
            "expires_at_unix_seconds": nowSeconds + 120,
            "submission_path": SiteRootConvergenceProfileV2.provisionPath,
        ])
        let value = try SiteRootBundleReceiptProvisionPresentationV1(
            qrText: qr, nowUnixSeconds: nowSeconds
        )
        XCTAssertNoThrow(try value.validateChallenge(deviceKeyID: "site-root-device"))
        XCTAssertThrowsError(try value.validateChallenge(deviceKeyID: "site-root-other"))
    }

    func testBundleReceiptRejectsExpiryAndUnknownMember() throws {
        var object: [String: Any] = [
            "schema": SiteRootConvergenceProfileV2.provisionSchema,
            "purpose": SiteRootConvergenceProfileV2.provisionPurpose,
            "correlation_b64url": b64(Data(repeating: 1, count: 16)),
            "canonical_challenge_b64url": b64(provisionChallenge(site: "site-demo", generation: 7)),
            "site_trust_domain": "site-demo", "receipt_key_generation": 7,
            "expires_at_unix_seconds": nowSeconds,
            "submission_path": SiteRootConvergenceProfileV2.provisionPath,
        ]
        XCTAssertThrowsError(try SiteRootBundleReceiptProvisionPresentationV1(
            qrText: json(object), nowUnixSeconds: nowSeconds
        ))
        object["expires_at_unix_seconds"] = nowSeconds + 60
        object["fallback"] = true
        XCTAssertThrowsError(try SiteRootBundleReceiptProvisionPresentationV1(
            qrText: json(object), nowUnixSeconds: nowSeconds
        ))
    }

    func testPXRAExactFrameParsesAndDriftFailsClosed() throws {
        let unsigned = pxra()
        let origin = URL(string: "https://192.168.1.192:8443")!
        let qr = json([
            "schema": SiteRootConvergenceProfileV2.ackSchema,
            "purpose": SiteRootConvergenceProfileV2.ackPurpose,
            "unsigned_pxra_v2_b64url": b64(unsigned),
            "submission_url": origin.absoluteString
                + SiteRootConvergenceProfileV2.ackSubmissionPath,
        ])
        let value = try SiteRootConvergenceAckPresentationV2(
            qrText: qr, authorityOrigin: origin,
            nowUnixMilliseconds: nowSeconds * 1_000
        )
        XCTAssertEqual(value.assertion.siteUUIDText, "01010101-0101-0101-0101-010101010101")
        XCTAssertEqual(value.assertion.action, .install)
        XCTAssertEqual(value.assertion.ackKeyGeneration, 3)

        var trailing = unsigned
        trailing.append(0)
        XCTAssertThrowsError(try UnsignedSiteRootConvergenceAssertionV2(
            trailing, nowUnixMilliseconds: nowSeconds * 1_000
        ))
    }

    func testSiteX509PresentationBindsAtomicDistinctRoles() throws {
        let site = Data(repeating: 2, count: 16)
        let transaction = Data(repeating: 3, count: 16)
        let challenge = x509Challenge(
            site: site, transaction: transaction, generation: 4
        )
        let qr = json([
            "schema": SiteRootConvergenceProfileV2.x509ProvisionSchema,
            "purpose": SiteRootConvergenceProfileV2.x509Purpose,
            "site_uuid": "02020202-0202-0202-0202-020202020202",
            "transaction_uuid": "03030303-0303-0303-0303-030303030303",
            "generation": 4,
            "canonical_challenge_b64url": b64(challenge),
            "roles": SiteX509FirstProvisionPresentationV1.roles,
            "expires_at_unix_seconds": nowSeconds + 120,
            "submission_path": SiteRootConvergenceProfileV2.x509SubmitPath,
        ])
        XCTAssertNoThrow(try SiteX509FirstProvisionPresentationV1(
            qrText: qr, nowUnixSeconds: nowSeconds
        ))

        var drift = try JSONSerialization.jsonObject(with: Data(qr.utf8)) as! [String: Any]
        drift["roles"] = ["site-x509-issuer", "site-x509-root"]
        XCTAssertThrowsError(try SiteX509FirstProvisionPresentationV1(
            qrText: json(drift), nowUnixSeconds: nowSeconds
        ))
    }

    func testBrokerAttemptProfileUsesFixedEndpointAndReservationSchema() throws {
        XCTAssertEqual(
            SiteRootConvergenceProfileV2.x509BrokerAttemptSchema,
            "mnemosyne.monas.first-install-broker.pistis-site-x509-first-provision-attempt.v1"
        )
        XCTAssertEqual(
            SiteRootConvergenceProfileV2.x509BrokerAttemptPath,
            "/api/first-install/v1/pistis/site-x509-first-provision/attempt"
        )
        XCTAssertEqual(
            SiteRootConvergenceProfileV2.x509BrokerAttemptResponseState,
            "reserved"
        )

        let presentation = try brokerPresentation()
        XCTAssertEqual(
            presentation.submissionURL.path,
            SiteRootConvergenceProfileV2.x509BrokerSubmitPath
        )
        XCTAssertEqual(
            SiteRootConvergenceProfileV2.x509BrokerOrigin,
            "https://install.mnemosyne.co.uk"
        )
    }

    func testBrokerPresentationAcceptsOptionalEnrolledSiteRootPublicKeyID() throws {
        let keyID = Data(repeating: 0x2a, count: 32)
        let presentation = try brokerPresentation(enrolledKeyID: keyID)
        XCTAssertEqual(presentation.enrolledSiteRootPublicKeyID, keyID)
    }

    func testBrokerPresentationRejectsMalformedOptionalEnrolledSiteRootPublicKeyID() {
        for value in [
            SiteRootConvergenceEncoding.encode(Data(repeating: 0x2a, count: 31)),
            SiteRootConvergenceEncoding.encode(Data(repeating: 0x2a, count: 33)),
            "\(SiteRootConvergenceEncoding.encode(Data(repeating: 0x2a, count: 32)))=",
        ] {
            XCTAssertThrowsError(try SiteX509FirstProvisionBrokerPresentationV1(
                qrText: brokerQR(enrolledKeyIDB64URL: value), nowUnixSeconds: nowSeconds
            ))
        }
    }

    func testBrokerEnrolledSiteRootPublicKeyIDAcceptsMatchingKey() throws {
        let publicKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 7, count: 32)
        ).publicKey.compressedRepresentation
        let keyID = Data(SHA256.hash(data: publicKey))
        XCTAssertNoThrow(try SiteRootConvergenceServiceV2
            .validateBrokerEnrolledSiteRootPublicKeyID(
                keyID, actualPublicKeyCompressedSEC1: publicKey
            ))
    }

    func testBrokerEnrolledSiteRootPublicKeyIDMismatchStopsBeforeSubmission() async throws {
        let publicKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 7, count: 32)
        ).publicKey.compressedRepresentation
        let presentation = try brokerPresentation(enrolledKeyID: Data(repeating: 0x2a, count: 32))
        let recorder = BrokerAttemptRecorder()
        let transport = RecordingBrokerTransport(recorder: recorder)
        let service = SiteRootConvergenceServiceV2(
            transport: transport,
            brokerProofFactory: { value in
                try SiteRootConvergenceServiceV2.validateBrokerEnrolledSiteRootPublicKeyID(
                    value.enrolledSiteRootPublicKeyID,
                    actualPublicKeyCompressedSEC1: publicKey
                )
                await recorder.record("proof")
                return Data([0x01])
            }
        )

        do {
            try await service.provisionSiteX509Broker(presentation)
            XCTFail("a mismatched enrolled Site Root key ID must deny the proof")
        } catch let failure as PlatformFailure {
            XCTAssertEqual(failure, .siteRootAuthorityKeyMismatch)
        }
        let events = await recorder.events()
        XCTAssertEqual(events, ["reserve"])
    }

    func testBrokerTransportUsesAttemptThenSubmissionEndpointsAndExactProfiles() async throws {
        BrokerTransportURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [BrokerTransportURLProtocol.self]
        let transport = try MonasSiteX509FirstProvisionBrokerTransport(
            session: URLSession(configuration: configuration)
        )
        let presentation = try brokerPresentation()

        try await transport.reserveSiteX509FirstProvisionBroker(presentation)
        try await transport.submitSiteX509FirstProvisionBroker(
            presentation, detachedCOSE: Data([0x01, 0x02])
        )

        let requests = BrokerTransportURLProtocol.requests()
        XCTAssertEqual(
            requests.map { $0.url?.path },
            [
                SiteRootConvergenceProfileV2.x509BrokerAttemptPath,
                SiteRootConvergenceProfileV2.x509BrokerSubmitPath,
            ]
        )
        for request in requests {
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/json")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Cache-Control"), "no-store")
        }

        let attempt = try XCTUnwrap(jsonObject(requests[0]))
        XCTAssertEqual(
            Set(attempt.keys),
            [
                "schema", "purpose", "correlation_b64url", "site_uuid", "transaction_uuid",
                "generation", "canonical_challenge_b64url", "roles",
            ]
        )
        XCTAssertEqual(
            attempt["schema"] as? String,
            SiteRootConvergenceProfileV2.x509BrokerAttemptSchema
        )
        XCTAssertEqual(
            attempt["purpose"] as? String,
            SiteRootConvergenceProfileV2.x509BrokerPurpose
        )
        XCTAssertEqual(
            attempt["roles"] as? [String],
            SiteX509FirstProvisionBrokerPresentationV1.roles
        )

        let submission = try XCTUnwrap(jsonObject(requests[1]))
        XCTAssertEqual(
            Set(submission.keys),
            [
                "schema", "purpose", "correlation_b64url", "site_uuid", "transaction_uuid",
                "generation", "canonical_challenge_b64url", "roles",
                "detached_cose_sign1_b64url",
            ]
        )
        XCTAssertEqual(
            submission["schema"] as? String,
            SiteRootConvergenceProfileV2.x509BrokerSubmissionSchema
        )
    }

    func testBrokerApprovalReservesBeforeProtectedProofAndCannotBeReplayed() async throws {
        let recorder = BrokerAttemptRecorder()
        let transport = RecordingBrokerTransport(recorder: recorder)
        let service = SiteRootConvergenceServiceV2(
            transport: transport,
            brokerProofFactory: { _ in
                await recorder.record("proof")
                return Data([0x01])
            }
        )
        let presentation = try brokerPresentation()

        try await service.provisionSiteX509Broker(presentation)
        let firstEvents = await recorder.events()
        XCTAssertEqual(firstEvents, ["reserve", "proof", "submit"])

        do {
            try await service.provisionSiteX509Broker(presentation)
            XCTFail("a reserved broker presentation must not be reusable")
        } catch let failure as PlatformFailure {
            XCTAssertEqual(failure, .siteRootAuthorityUnavailable)
        }
        let replayEvents = await recorder.events()
        XCTAssertEqual(replayEvents, ["reserve", "proof", "submit", "reserve"])
    }

    func testPurposeSpecificProtectedHeadersAreCanonical() throws {
        let kid = Data(repeating: 9, count: 8)
        let contentType = SiteRootConvergenceProfileV2.pxraContentType
        let value = try DetachedES256Cose.protectedHeaders(
            kid: kid, contentType: contentType
        )
        let expected = Data([0xa3, 0x01, 0x26, 0x03, 0x78, UInt8(contentType.utf8.count)])
            + Data(contentType.utf8) + Data([0x04, 0x48]) + kid
        XCTAssertEqual(value, expected)
    }

    private func provisionChallenge(site: String, generation: UInt64) -> Data {
        var result = Data()
        result += field(1, Data("mnemosyne.thesaurophylax.site-root-bundle-receipt-provision.v1".utf8))
        result += field(2, Data(SiteRootConvergenceProfileV2.provisionPurpose.utf8))
        result += field(3, Data(site.utf8))
        result += field(4, Data("site-root-bundle-receipt-\(generation)".utf8))
        result += field(5, Data("site-root-device".utf8))
        result += field(6, Data([2]) + Data(repeating: 4, count: 32))
        result += field(7, Data(repeating: 5, count: 32))
        return result
    }

    private func pxra() -> Data {
        let issued = nowSeconds * 1_000 - 1_000
        var value = Data("PXRA/v2\u{1}".utf8)
        value += field(1, Data(repeating: 1, count: 16))
        value += field(2, Data(repeating: 2, count: 32))
        value += field(3, Data([1]))
        value += field(4, Data(repeating: 3, count: 16))
        value += field(5, u64(1))
        value += field(6, u64(2))
        value += field(7, Data(repeating: 4, count: 32))
        value += field(8, Data([1]))
        value += field(9, Data())
        value += field(10, u64(issued))
        value += field(11, u64(issued + 120_000))
        value += field(12, Data(repeating: 5, count: 32))
        value += field(13, u64(3))
        return value
    }

    private func x509Challenge(site: Data, transaction: Data, generation: UInt64) -> Data {
        var value = Data("PXFP/v1\u{1}".utf8)
        value += field(1, Data(SiteRootConvergenceProfileV2.x509Purpose.utf8))
        value += field(2, site)
        value += field(3, transaction)
        value += field(4, u64(generation))
        value += field(5, Data(SiteRootConvergenceProfileV2.x509RootPurpose.utf8))
        value += field(6, Data([2]) + Data(repeating: 6, count: 32))
        value += field(7, Data(repeating: 7, count: 32))
        value += field(8, Data(repeating: 8, count: 32))
        value += field(9, Data(SiteRootConvergenceProfileV2.x509IssuerPurpose.utf8))
        value += field(10, Data([3]) + Data(repeating: 9, count: 32))
        value += field(11, Data(repeating: 10, count: 32))
        value += field(12, Data(repeating: 11, count: 32))
        value += field(13, u64(nowSeconds + 120))
        value += field(14, Data(repeating: 12, count: 32))
        return value
    }

    private func brokerPresentation(
        enrolledKeyID: Data? = nil
    ) throws -> SiteX509FirstProvisionBrokerPresentationV1 {
        try SiteX509FirstProvisionBrokerPresentationV1(
            qrText: brokerQR(enrolledKeyIDB64URL: enrolledKeyID.map(b64)),
            nowUnixSeconds: nowSeconds
        )
    }

    private func brokerQR(enrolledKeyIDB64URL: String? = nil) -> String {
        let site = Data(repeating: 2, count: 16)
        let transaction = Data(repeating: 3, count: 16)
        var object: [String: Any] = [
            "schema": SiteRootConvergenceProfileV2.x509BrokerProvisionSchema,
            "purpose": SiteRootConvergenceProfileV2.x509BrokerPurpose,
            "site_uuid": "02020202-0202-0202-0202-020202020202",
            "transaction_uuid": "03030303-0303-0303-0303-030303030303",
            "generation": 4,
            "canonical_challenge_b64url": b64(
                x509Challenge(site: site, transaction: transaction, generation: 4)
            ),
            "correlation_b64url": b64(Data(repeating: 4, count: 32)),
            "roles": SiteX509FirstProvisionBrokerPresentationV1.roles,
            "expires_at_unix_seconds": nowSeconds + 120,
            "submission_url": SiteRootConvergenceProfileV2.x509BrokerOrigin
                + SiteRootConvergenceProfileV2.x509BrokerSubmitPath,
        ]
        if let enrolledKeyIDB64URL {
            object["enrolled_site_root_public_key_id_b64url"] = enrolledKeyIDB64URL
        }
        return json(object)
    }

    private func field(_ tag: UInt8, _ value: Data) -> Data {
        Data([tag, UInt8(value.count >> 8), UInt8(truncatingIfNeeded: value.count)]) + value
    }

    private func u64(_ value: UInt64) -> Data {
        SiteRootConvergenceEncoding.uint64Bytes(value)
    }

    private func b64(_ value: Data) -> String { SiteRootConvergenceEncoding.encode(value) }

    private func json(_ object: [String: Any]) -> String {
        String(data: try! JSONSerialization.data(withJSONObject: object), encoding: .utf8)!
    }

    private func jsonObject(_ request: URLRequest) throws -> [String: Any] {
        let body = try XCTUnwrap(request.httpBody)
        return try XCTUnwrap(
            JSONSerialization.jsonObject(with: body) as? [String: Any]
        )
    }
}

private actor BrokerAttemptRecorder {
    private var values: [String] = []
    private var reservationCount = 0

    func record(_ value: String) {
        values.append(value)
    }

    func reserve() throws {
        reservationCount += 1
        values.append("reserve")
        guard reservationCount == 1 else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
    }

    func events() -> [String] { values }
}

private struct RecordingBrokerTransport: MonasSiteRootConvergenceSubmitting {
    let authorityOrigin = URL(string: SiteRootConvergenceProfileV2.x509BrokerOrigin)!
    let recorder: BrokerAttemptRecorder

    func submitBundleReceiptProvision(
        _: SiteRootBundleReceiptProvisionPresentationV1,
        detachedCOSE _: Data
    ) async throws -> UInt64 {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }

    func submitSiteX509FirstProvision(
        _: SiteX509FirstProvisionPresentationV1,
        detachedCOSE _: Data
    ) async throws {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }

    func reserveSiteX509FirstProvisionBroker(
        _: SiteX509FirstProvisionBrokerPresentationV1
    ) async throws {
        try await recorder.reserve()
    }

    func submitSiteX509FirstProvisionBroker(
        _: SiteX509FirstProvisionBrokerPresentationV1,
        detachedCOSE _: Data
    ) async throws {
        await recorder.record("submit")
    }

    func registerAckKey(
        _: SiteRootConvergenceAckRegistrationV2
    ) async throws -> SiteRootConvergenceAckRegistrationResultV2 {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }

    func submitAck(_: Data, endpoint _: URL) async throws {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }

    func fetchBundleReceiptUnlock(
        nowUnixSeconds _: UInt64
    ) async throws -> IphoneMediatedCustodyRewrapPresentationV1 {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }

    func submitBundleReceiptUnlock(
        _: IphoneMediatedCustodyRewrapSubmissionV1
    ) async throws {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }
}

private final class BrokerTransportURLProtocol: URLProtocol, @unchecked Sendable {
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
        guard let url = request.url else {
            client?.urlProtocol(self, didFailWithError: PlatformFailure.invalidConfiguration)
            return
        }
        Self.lock.lock()
        var captured = request
        captured.httpBody = request.httpBody ?? Self.readBody(from: request.httpBodyStream)
        Self.capturedRequests.append(captured)
        Self.lock.unlock()

        let state = url.path == SiteRootConvergenceProfileV2.x509BrokerAttemptPath
            ? SiteRootConvergenceProfileV2.x509BrokerAttemptResponseState
            : "accepted"
        let body = Data(
            "{\"schema\":\"\(SiteRootConvergenceProfileV2.x509BrokerResponseSchema)\",\"state\":\"\(state)\"}".utf8
        )
        let response = HTTPURLResponse(
            url: url,
            statusCode: 202,
            httpVersion: nil,
            headerFields: [
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            ]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

    private static func readBody(from stream: InputStream?) -> Data? {
        guard let stream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 1_024)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            guard count > 0 else { break }
            data.append(buffer, count: count)
        }
        return data
    }
}
