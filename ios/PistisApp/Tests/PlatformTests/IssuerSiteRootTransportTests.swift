import Foundation
import PistisCore
import XCTest
@testable import Pistis

final class IssuerSiteRootTransportTests: XCTestCase {
    override func tearDown() {
        IssuerURLProtocol.reset()
        super.tearDown()
    }
    private func transport() throws -> IssuerSiteRootTransport {
        let settings = URLSessionConfiguration.ephemeral
        settings.protocolClasses = [IssuerURLProtocol.self]
        return try IssuerSiteRootTransport(origin: XCTUnwrap(URL(string: "https://monas.example.test")), session: URLSession(configuration: settings))
    }
    func testFixedCBORPathsNoCookiesOrCacheAndOriginalDeadline() async throws {
        IssuerURLProtocol.configure(status: 200, headers: ["Content-Type":"application/cbor", "Cache-Control":"no-store"], body: Data([0x80]))
        let transport = try transport()
        let deadline = ContinuousClock().now.advanced(by: .seconds(2))
        let result = try await transport.exchange(Data([0x80]), deadline: deadline)
        XCTAssertEqual(result, Data([0x80]))
        let request = try XCTUnwrap(IssuerURLProtocol.requests().first)
        XCTAssertEqual(request.url?.absoluteString, "https://monas.example.test" + IssuerPhoneWire.exchangePath)
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/cbor")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Accept-Encoding"), "identity")
        XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))
        XCTAssertFalse(request.httpShouldHandleCookies)
        XCTAssertLessThanOrEqual(request.timeoutInterval, 2)
        do {
            _ = try await transport.exchange(Data([0x80]), deadline: ContinuousClock().now)
            XCTFail("expired original budget reached transport")
        } catch { XCTAssertEqual(error as? IssuerPhoneError, .expired) }
        XCTAssertEqual(IssuerURLProtocol.requests().count, 1)
    }
    func testResponseTypeCompressionCookieAndAggregateCapsDeny() async throws {
        let transport = try transport()
        let cases: [(Int, [String:String], Data)] = [
            (302, ["Content-Type":"application/cbor", "Cache-Control":"no-store"], Data([0x80])),
            (200, ["Content-Type":"application/json", "Cache-Control":"no-store"], Data([0x80])),
            (200, ["Content-Type":"application/cbor", "Cache-Control":"no-store", "Content-Encoding":"gzip"], Data([0x80])),
            (200, ["Content-Type":"application/cbor", "Cache-Control":"no-store", "Set-Cookie":"untrusted=value"], Data([0x80])),
            (200, ["Content-Type":"application/cbor", "Cache-Control":"no-store"], Data(repeating: 0, count: 262145)),
        ]
        for (status, headers, body) in cases {
            IssuerURLProtocol.configure(status: status, headers: headers, body: body)
            do {
                _ = try await transport.readiness(Data([0x80]), deadline: ContinuousClock().now.advanced(by: .seconds(2)))
                XCTFail("hostile response accepted")
            } catch {}
        }
    }
    @MainActor
    func testMissingGenuinePreparedOwnerRemainsClosedWithoutKeyInvocation() throws {
        XCTAssertThrowsError(try IssuerSiteRootPreparedHandoff.current())
    }
}

private final class IssuerURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var status = 200
    nonisolated(unsafe) private static var headers: [String:String] = [:]
    nonisolated(unsafe) private static var body = Data()
    nonisolated(unsafe) private static var seen: [URLRequest] = []
    static func configure(status: Int, headers: [String:String], body: Data) {
        lock.lock(); defer { lock.unlock() }
        Self.status = status; Self.headers = headers; Self.body = body
    }
    static func reset() {
        lock.lock(); defer { lock.unlock() }
        status = 200; headers = [:]; body = Data(); seen = []
    }
    static func requests() -> [URLRequest] {
        lock.lock(); defer { lock.unlock() }; return seen
    }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.lock.lock()
        Self.seen.append(request)
        let status = Self.status, headers = Self.headers, body = Self.body
        Self.lock.unlock()
        guard let url = request.url, let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers) else { return }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        // Deliberately deliver multiple chunks to exercise aggregate accounting.
        for offset in stride(from: 0, to: body.count, by: 4096) {
            client?.urlProtocol(self, didLoad: body.subdata(in: offset..<min(body.count, offset+4096)))
        }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
