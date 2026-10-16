import Foundation
import PistisCore
import XCTest
@testable import Pistis

final class IssuerNativeSessionTransportTests: XCTestCase {
    override func tearDown() { NativeIssuerURLProtocol.reset(); super.tearDown() }
    private func transport() throws -> IssuerNativeSessionTransport {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [NativeIssuerURLProtocol.self]
        return try IssuerNativeSessionTransport(testOrigin: XCTUnwrap(URL(string: "https://monas.example.test")),
            session: URLSession(configuration: config))
    }
    func testNativeFixedProfileUsesOwnBeginSecretWithoutBrowserState() async throws {
        NativeIssuerURLProtocol.configure(headers: ["Content-Type": "application/json", "Cache-Control": "no-store"], body: Data("{}".utf8))
        let transport = try transport()
        let deadline = ContinuousClock().now.advanced(by: .seconds(2))
        _ = try await transport.begin(enrollment: nativeIssuerEnrollmentDataFixture(), deadline: deadline)
        _ = try await transport.finalize(reference: "fixture", secret: Data(repeating: 8, count: 32), deadline: deadline)
        let requests = NativeIssuerURLProtocol.requests()
        XCTAssertEqual(requests.map { $0.url!.path }, [IssuerNativeSessionWire.beginPath, IssuerNativeSessionWire.finalizePath])
        for request in requests {
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Pistis-Session-Profile"), IssuerNativeSessionWire.profile)
            XCTAssertNil(request.value(forHTTPHeaderField: "Cookie")); XCTAssertNil(request.value(forHTTPHeaderField: "Origin"))
            XCTAssertNil(request.value(forHTTPHeaderField: "Authorization")); XCTAssertFalse(request.httpShouldHandleCookies)
            XCTAssertLessThanOrEqual(request.timeoutInterval, 2)
        }
        XCTAssertEqual(requests[0].value(forHTTPHeaderField: "Pistis-Native-Key-ID"), String(repeating: "ab", count: 32))
        XCTAssertEqual(requests[0].value(forHTTPHeaderField: "Pistis-Native-Device-ID"), "44444444-4444-4444-8444-444444444444")
        let body = try StrictJSONObject(data: XCTUnwrap(requests[1].httpBody), maximumBytes: 1024).values
        XCTAssertEqual(body["browser_secret"], .string(IssuerNativeSessionWire.encode(Data(repeating: 8, count: 32))))
        XCTAssertEqual(Set(body.keys), ["reference", "browser_secret"])
    }
    func testSubmitKeepsExistingCOSEAndNoStatusRetryOrCookieResponse() async throws {
        NativeIssuerURLProtocol.configure(headers: ["Content-Type": "application/json"], body: Data("{\"state\":\"completed\",\"evidence_id\":null}".utf8))
        let transport = try transport()
        let challenge = UUID(uuidString: "77777777-7777-4777-8777-777777777777")!
        let data = try await transport.submit(Data([0x84]), challengeID: challenge, deadline: ContinuousClock().now.advanced(by: .seconds(2)))
        try IssuerNativeSessionWire.completedStatus(data)
        XCTAssertEqual(NativeIssuerURLProtocol.requests().count, 1)
        let request = try XCTUnwrap(NativeIssuerURLProtocol.requests().first)
        XCTAssertEqual(request.url?.absoluteString, "https://monas.example.test/auth/pistis/v2/submit?challenge_id=77777777-7777-4777-8777-777777777777")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/cose")
        NativeIssuerURLProtocol.configure(headers: ["Content-Type": "application/json", "Cache-Control": "no-store", "Set-Cookie": "forbidden=1"], body: Data("{}".utf8))
        do { _ = try await transport.finalize(reference: "fixture", secret: Data(repeating: 8, count: 32), deadline: ContinuousClock().now.advanced(by: .seconds(2))); XCTFail("cookie accepted") } catch {}
        let count = NativeIssuerURLProtocol.requests().count
        do { _ = try await transport.finalize(reference: "fixture", secret: Data(repeating: 8, count: 32), deadline: ContinuousClock().now); XCTFail("expired request dispatched") } catch {}
        XCTAssertEqual(NativeIssuerURLProtocol.requests().count, count)
    }
}

private final class NativeIssuerURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var headers: [String: String] = [:]
    nonisolated(unsafe) private static var body = Data()
    nonisolated(unsafe) private static var seen: [URLRequest] = []
    static func configure(headers: [String: String], body: Data) { lock.lock(); defer { lock.unlock() }; Self.headers = headers; Self.body = body }
    static func reset() { lock.lock(); defer { lock.unlock() }; headers = [:]; body = Data(); seen = [] }
    static func requests() -> [URLRequest] { lock.lock(); defer { lock.unlock() }; return seen }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        // URLSession may carry a POST body as a stream at the URLProtocol boundary.
        // Capture the actual bounded bytes so assertions still inspect what was sent.
        var captured = request
        if captured.httpBody == nil, let stream = captured.httpBodyStream {
            stream.open()
            defer { stream.close() }
            var bytes = Data()
            var buffer = [UInt8](repeating: 0, count: 256)
            while stream.hasBytesAvailable {
                let count = stream.read(&buffer, maxLength: buffer.count)
                guard count >= 0, bytes.count + count <= 1024 else {
                    client?.urlProtocol(self, didFailWithError: URLError(.dataLengthExceedsMaximum))
                    return
                }
                if count == 0 { break }
                bytes.append(contentsOf: buffer.prefix(count))
            }
            captured.httpBody = bytes
        }
        Self.lock.lock(); Self.seen.append(captured); let headers = Self.headers, body = Self.body; Self.lock.unlock()
        guard let url = request.url, let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers) else { return }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body); client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
