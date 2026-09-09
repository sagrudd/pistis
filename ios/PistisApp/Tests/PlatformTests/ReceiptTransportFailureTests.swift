import Foundation
import XCTest
@testable import Pistis

final class ReceiptTransportFailureTests: XCTestCase {
    private let endpoint = URL(string: "https://receipt.example.test:8443/presentation")!

    func testActualSubmissionConformsToInstalledMonasHTTPContract() async throws {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0 ..< 5 { root.deleteLastPathComponent() }
        let contract = try JSONDecoder().decode(ReceiptHTTPContract.self, from:
            Data(contentsOf: root.appendingPathComponent("fixtures/receipt-http-v1/contract.json")))
        XCTAssertEqual(contract.sourceRevision, "03f7877440581b41d83e333fbadb52a1d8c3f020")
        XCTAssertEqual(contract.fields.count, 9)
        ReceiptTestURLProtocol.capture.reset(contract: contract)
        defer { ReceiptTestURLProtocol.capture.reset() }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ReceiptTestURLProtocol.self]
        let transport = try MonasSiteRootConvergenceTransport(
            authorityOrigin: URL(string: "https://receipt.example.test:8443")!,
            trustPolicy: .bootstrapLeafSPKI(Data(repeating: 1, count: 32)),
            configuration: configuration
        )
        let submission = IphoneMediatedCustodyRewrapSubmissionV1(
            correlation: Data(repeating: 1, count: 16), canonicalPayload: Data([1]),
            deviceKeyID: "synthetic", delegationSerial: "synthetic", siteTrustDomain: "synthetic",
            purpose: SiteRootBundleReceiptRewrapV1.purpose, coseSign1: Data([1]), rewrappedCiphertext: Data([1])
        )
        // This is the real request producer, not a hand-written request fixture.
        try await transport.submitBundleReceiptUnlock(submission)
        let requests = ReceiptTestURLProtocol.capture.requests()
        XCTAssertEqual(requests.count, 1)
        let sent = try XCTUnwrap(requests.first)
        XCTAssertEqual(sent.httpMethod, "POST")
        XCTAssertEqual(sent.url?.absoluteString,
                       "https://receipt.example.test:8443/v1/pistis/site-root-bundle-receipt-unlock/submit")
        XCTAssertEqual(sent.value(forHTTPHeaderField: "Content-Type"), contract.contentType)
        let body = try XCTUnwrap(sent.httpBody)
        let fields = try JSONDecoder().decode([String: String].self, from: body)
        XCTAssertEqual(Set(fields.keys), Set(contract.fields))
        XCTAssertEqual(fields["schema"], contract.schema)

        // Replay only synthetic captured test bytes through the isolated adapter.
        // The old header cannot reach synthetic acceptance; no live proof exists.
        let session = URLSession(configuration: configuration)
        var old = sent
        old.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        let (_, rejected) = try await session.data(for: old)
        XCTAssertEqual((rejected as? HTTPURLResponse)?.statusCode, 400)
        for extra in [false, true] {
            var changed = fields
            if extra { changed["unknown"] = "synthetic" }
            else { changed.removeValue(forKey: "schema") }
            var invalid = sent
            invalid.httpBody = try JSONEncoder().encode(changed)
            let (_, response) = try await session.data(for: invalid)
            XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 400)
        }
    }

    func testKnownNetworkCategoriesAndUnknownDetailsAreNeverRendered() {
        let cases: [(URLError.Code, SiteRootReceiptTransportFailure.Reason)] = [
            (.cancelled, .cancelled), (.timedOut, .timeout),
            (.notConnectedToInternet, .offline), (.dataNotAllowed, .offline),
            (.internationalRoamingOff, .offline), (.secureConnectionFailed, .tls),
            (.serverCertificateHasBadDate, .tls), (.serverCertificateUntrusted, .tls),
            (.serverCertificateHasUnknownRoot, .tls), (.serverCertificateNotYetValid, .tls),
            (.clientCertificateRejected, .tls), (.clientCertificateRequired, .tls),
            (.cannotFindHost, .dns), (.dnsLookupFailed, .dns),
            (.cannotConnectToHost, .connection), (.networkConnectionLost, .connectionLost),
            (.userCancelledAuthentication, .authenticationChallenge), (.unknown, .network)
        ]
        for (code, reason) in cases {
            let error = URLError(code, userInfo: [NSLocalizedDescriptionKey: "DO_NOT_DISCLOSE"])
            for operation in [SiteRootReceiptTransportFailure.Operation.presentation, .submission] {
                let failure = SiteRootReceiptTransportFailure.network(error, operation: operation)
                XCTAssertEqual(failure.reason, reason)
                XCTAssertFalse(failure.message.contains("DO_NOT_DISCLOSE"))
                if operation == .submission {
                    XCTAssertTrue(failure.message.contains("not confirmed"))
                    XCTAssertFalse(failure.message.contains("No proof"))
                }
            }
        }
        XCTAssertEqual(SiteRootReceiptTransportFailure.network(
            NSError(domain: "DO_NOT_DISCLOSE", code: 123), operation: .presentation
        ).reason, .network)
        XCTAssertEqual(SiteRootReceiptTransportFailure.network(
            CancellationError(), operation: .submission
        ).reason, .cancelled)
        XCTAssertEqual(SiteRootReceiptTransportFailure.Reason.httpStatus(999_999).code, "invalid-status")
        XCTAssertEqual(SiteRootReceiptTransportFailure.Reason.httpStatus(-1).code, "invalid-status")
    }

    func testExactResponsePredicatesAndOperationSpecificFailures() throws {
        func response(_ status: Int, headers: [String: String] = ["Cache-Control": "no-store"],
                      url: URL? = nil) -> HTTPURLResponse {
            HTTPURLResponse(url: url ?? endpoint, statusCode: status, httpVersion: nil, headerFields: headers)!
        }
        func denied(_ data: Data, _ response: URLResponse,
                    _ operation: SiteRootReceiptTransportFailure.Operation,
                    _ reason: SiteRootReceiptTransportFailure.Reason) {
            XCTAssertThrowsError(try SiteRootReceiptTransportFailure.validate(
                data: data, response: response, endpoint: endpoint, operation: operation
            )) { error in
                XCTAssertEqual(error as? PlatformFailure, .siteRootReceiptTransport(
                    .init(operation: operation, reason: reason)
                ))
            }
        }
        let body = Data([1])
        XCTAssertNoThrow(try SiteRootReceiptTransportFailure.validate(
            data: body, response: response(200), endpoint: endpoint, operation: .presentation))
        XCTAssertNoThrow(try SiteRootReceiptTransportFailure.validate(
            data: Data(), response: response(202), endpoint: endpoint, operation: .submission))
        for status in [301, 401, 403, 404, 409, 410, 422, 500, 503] {
            denied(body, response(status), .presentation, .httpStatus(status))
            denied(Data(), response(status), .submission, .httpStatus(status))
        }
        denied(body, response(200, headers: [:]), .presentation, .cacheControl)
        denied(Data(), response(202, headers: [:]), .submission, .cacheControl)
        denied(Data(), response(200), .presentation, .emptyPresentation)
        denied(Data(repeating: 1, count: 16_385), response(200), .presentation, .oversizedPresentation)
        denied(body, response(202), .submission, .submissionBody)
        denied(body, response(200, url: URL(string: "https://other.example.test")!), .presentation, .endpoint)
        denied(body, URLResponse(url: endpoint, mimeType: nil, expectedContentLength: 1,
                                textEncodingName: nil), .presentation, .nonHTTP)
    }

    func testOnlyExistingPostProvisionPresentationRetryEligibilityIsPreserved() {
        XCTAssertTrue(SiteRootBundleReceiptUnlockReadiness.retryablePresentationFailure(
            .siteRootAuthorityUnavailable))
        XCTAssertTrue(SiteRootBundleReceiptUnlockReadiness.retryablePresentationFailure(
            .siteRootReceiptTransport(.init(operation: .presentation, reason: .httpStatus(503)))))
        XCTAssertFalse(SiteRootBundleReceiptUnlockReadiness.retryablePresentationFailure(
            .siteRootReceiptTransport(.init(operation: .submission, reason: .httpStatus(503)))))
        XCTAssertFalse(SiteRootBundleReceiptUnlockReadiness.retryablePresentationFailure(.custodyRewrapUnavailable))
    }

    func testActualReceiptRequestsUseExactBoundOriginAndDistinguishGetPost() async throws {
        let origin = URL(string: "https://receipt.example.test:8443")!
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ReceiptTestURLProtocol.self]
        let transport = try MonasSiteRootConvergenceTransport(
            authorityOrigin: origin, trustPolicy: .bootstrapLeafSPKI(Data(repeating: 1, count: 32)),
            configuration: configuration
        )
        ReceiptTestURLProtocol.capture.reset()
        do {
            _ = try await transport.fetchBundleReceiptUnlock(nowUnixSeconds: 1_900_000_000)
            XCTFail("synthetic 503 must fail")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .siteRootReceiptTransport(
                .init(operation: .presentation, reason: .httpStatus(503))))
        }
        let value = IphoneMediatedCustodyRewrapSubmissionV1(
            correlation: Data(repeating: 1, count: 16), canonicalPayload: Data([1]),
            deviceKeyID: "synthetic", delegationSerial: "synthetic", siteTrustDomain: "synthetic",
            purpose: SiteRootBundleReceiptRewrapV1.purpose, coseSign1: Data([1]), rewrappedCiphertext: Data([1])
        )
        do {
            try await transport.submitBundleReceiptUnlock(value)
            XCTFail("synthetic 503 must fail")
        } catch {
            XCTAssertEqual(error as? PlatformFailure, .siteRootReceiptTransport(
                .init(operation: .submission, reason: .httpStatus(503))))
        }
        let requests = ReceiptTestURLProtocol.capture.requests()
        XCTAssertEqual(requests.map(\.httpMethod), ["GET", "POST"])
        XCTAssertEqual(requests.map { $0.url?.absoluteString }, [
            origin.absoluteString + "/v1/pistis/site-root-bundle-receipt-unlock/presentation",
            origin.absoluteString + "/v1/pistis/site-root-bundle-receipt-unlock/submit"
        ])
        XCTAssertTrue(requests.allSatisfy { $0.timeoutInterval == 15 })
        XCTAssertTrue(requests.allSatisfy { $0.value(forHTTPHeaderField: "Cache-Control") == "no-store" })
        let invalid = IphoneMediatedCustodyRewrapSubmissionV1(
            correlation: value.correlation, canonicalPayload: value.canonicalPayload,
            deviceKeyID: value.deviceKeyID, delegationSerial: value.delegationSerial,
            siteTrustDomain: value.siteTrustDomain, purpose: "wrong",
            coseSign1: value.coseSign1, rewrappedCiphertext: value.rewrappedCiphertext
        )
        do {
            try await transport.submitBundleReceiptUnlock(invalid)
            XCTFail("wrong purpose must fail before sending")
        } catch { XCTAssertEqual(error as? PlatformFailure, .siteRootReceiptSubmissionInvalid) }
        XCTAssertEqual(ReceiptTestURLProtocol.capture.requests().count, 2)
    }
}

/// Isolated URLSession adapter: all input/output is synthetic and no socket is opened.
private final class ReceiptTestURLProtocol: URLProtocol, @unchecked Sendable {
    final class Capture: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [URLRequest] = []
        private var contract: ReceiptHTTPContract?
        func reset(contract: ReceiptHTTPContract? = nil) {
            lock.lock(); defer { lock.unlock() }; values = []; self.contract = contract
        }
        func status(for request: URLRequest) -> Int {
            lock.lock(); defer { lock.unlock() }
            values.append(request)
            guard let contract else { return 503 }
            guard request.value(forHTTPHeaderField: "Content-Type") == contract.contentType,
                  let body = request.httpBody,
                  let values = try? JSONDecoder().decode([String: String].self, from: body),
                  Set(values.keys) == Set(contract.fields)
            else { return 400 }
            return values["schema"] == contract.schema ? 202 : 403
        }
        func requests() -> [URLRequest] { lock.lock(); defer { lock.unlock() }; return values }
    }
    static let capture = Capture()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        // URLSession may hand URLProtocol the unchanged upload bytes as a
        // stream rather than httpBody. Read only that bounded synthetic input;
        // never fabricate a body to make the admission adapter succeed.
        var captured = request
        if captured.httpBody == nil, let stream = request.httpBodyStream {
            let body = Self.readBody(stream)
            captured.httpBodyStream = nil
            captured.httpBody = body
        }
        let status = Self.capture.status(for: captured)
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil,
                                       headerFields: ["Cache-Control": "no-store"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}

    private static func readBody(_ stream: InputStream) -> Data? {
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4_096)
        while true {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count < 0 { return nil }
            if count == 0 { return data }
            data.append(contentsOf: buffer.prefix(count))
            if data.count > 16_384 { return nil }
        }
    }
}

private struct ReceiptHTTPContract: Decodable {
    let sourceRevision: String
    let contentType: String
    let schema: String
    let fields: [String]
    enum CodingKeys: String, CodingKey {
        case sourceRevision = "source_revision"
        case contentType = "content_type"
        case schema, fields
    }
}
