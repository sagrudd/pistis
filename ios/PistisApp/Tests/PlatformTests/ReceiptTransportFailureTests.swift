import Foundation
import XCTest
@testable import Pistis

final class ReceiptTransportFailureTests: XCTestCase {
    private let endpoint = URL(string: "https://receipt.example.test:8443/presentation")!

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
        func reset() { lock.lock(); defer { lock.unlock() }; values = [] }
        func append(_ request: URLRequest) { lock.lock(); defer { lock.unlock() }; values.append(request) }
        func requests() -> [URLRequest] { lock.lock(); defer { lock.unlock() }; return values }
    }
    static let capture = Capture()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.capture.append(request)
        let response = HTTPURLResponse(url: request.url!, statusCode: 503, httpVersion: nil,
                                       headerFields: ["Cache-Control": "no-store"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
