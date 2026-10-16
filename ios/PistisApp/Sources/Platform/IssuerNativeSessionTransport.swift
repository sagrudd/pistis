import Foundation
import PistisCore

#if canImport(Security)
/// One enrolled origin/SPKI, no redirect, cookie, cache, alternate host or retry.
final class IssuerNativeSessionTransport: @unchecked Sendable {
    let origin: URL
    private let session: URLSession
    init(enrollment: AuthenticatedEnrollmentOutput) throws {
        guard let canonical = CanonicalHTTPSOrigin.parse(enrollment.httpsOrigin),
              let origin = URL(string: canonical), let host = CanonicalHTTPSHost.from(origin),
              enrollment.allowedHosts.contains(host) else { throw IssuerPhoneError.binding }
        self.origin = origin
        let config = URLSessionConfiguration.ephemeral
        config.httpShouldSetCookies = false; config.httpCookieStorage = nil
        config.urlCache = nil; config.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(configuration: config, delegate: try PinnedEnrolmentSessionDelegate(
            origin: origin, expectedSPKISHA256: enrollment.tlsSPKISHA256), delegateQueue: nil)
    }
    #if DEBUG
    /// DATA transport fixture only; cannot construct a private current session.
    init(testOrigin: URL, session: URLSession) throws {
        guard CanonicalHTTPSOrigin.parse(testOrigin.absoluteString) != nil else { throw IssuerPhoneError.binding }
        origin = testOrigin; self.session = session
    }
    #endif
    func begin(enrollment: AuthenticatedEnrollmentOutput, deadline: ContinuousClock.Instant) async throws -> Data {
        var request = try fixedRequest(path: IssuerNativeSessionWire.beginPath, deadline: deadline)
        request.httpBody = try JSONSerialization.data(withJSONObject: ["principal_id": try IssuerNativeSessionWire.uuid(enrollment.trust.userID).uuidString.lowercased()], options: [.sortedKeys])
        request.setValue(try IssuerNativeSessionWire.uuid(enrollment.trust.installationID).uuidString.lowercased(), forHTTPHeaderField: "Pistis-Native-Installation-ID")
        request.setValue(try IssuerNativeSessionWire.uuid(enrollment.responseContext.deviceID).uuidString.lowercased(), forHTTPHeaderField: "Pistis-Native-Device-ID")
        request.setValue(IssuerNativeSessionWire.hex(enrollment.responseContext.deviceKeyID), forHTTPHeaderField: "Pistis-Native-Key-ID")
        return try await post(request, deadline: deadline, requireNoStore: true)
    }
    func submit(_ envelope: Data, challengeID: UUID, deadline: ContinuousClock.Instant) async throws -> Data {
        guard !envelope.isEmpty, envelope.count <= AuthenticationResponseTransport.maximumEnvelopeBytes else { throw IssuerPhoneError.bound }
        var request = try fixedRequest(path: IssuerNativeSessionWire.submitPath, deadline: deadline)
        guard let requestURL = request.url,
              var components = URLComponents(url: requestURL, resolvingAgainstBaseURL: false) else { throw IssuerPhoneError.binding }
        components.queryItems = [URLQueryItem(name: "challenge_id", value: challengeID.uuidString.lowercased())]
        guard let endpoint = components.url else { throw IssuerPhoneError.binding }
        request.url = endpoint; request.httpBody = envelope
        request.setValue("application/cose", forHTTPHeaderField: "Content-Type")
        return try await post(request, deadline: deadline, requireNoStore: false)
    }
    func finalize(reference: String, secret: Data, deadline: ContinuousClock.Instant) async throws -> Data {
        var request = try fixedRequest(path: IssuerNativeSessionWire.finalizePath, deadline: deadline)
        request.httpBody = try JSONSerialization.data(withJSONObject: ["reference": reference,
            "browser_secret": IssuerNativeSessionWire.encode(secret)], options: [.sortedKeys])
        return try await post(request, deadline: deadline, requireNoStore: true)
    }
    func expectedSubmit(challengeID: UUID) throws -> URL {
        guard var components = URLComponents(string: origin.absoluteString + IssuerNativeSessionWire.submitPath) else { throw IssuerPhoneError.binding }
        components.queryItems = [URLQueryItem(name: "challenge_id", value: challengeID.uuidString.lowercased())]
        guard let url = components.url else { throw IssuerPhoneError.binding }; return url
    }
    private func fixedRequest(path: String, deadline: ContinuousClock.Instant) throws -> URLRequest {
        let clock = ContinuousClock()
        try Task.checkCancellation()
        guard clock.now < deadline,
              [IssuerNativeSessionWire.beginPath, IssuerNativeSessionWire.submitPath, IssuerNativeSessionWire.finalizePath].contains(path),
              let endpoint = URL(string: path, relativeTo: origin)?.absoluteURL,
              CanonicalHTTPSOrigin.from(endpoint) == origin.absoluteString else { throw IssuerPhoneError.expired }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"; request.httpShouldHandleCookies = false
        request.setValue(IssuerNativeSessionWire.profile, forHTTPHeaderField: "Pistis-Session-Profile")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        let remaining = clock.now.duration(to: deadline).components
        request.timeoutInterval = Double(remaining.seconds) + Double(remaining.attoseconds) / 1e18
        return request
    }
    private func post(_ request: URLRequest, deadline: ContinuousClock.Instant, requireNoStore: Bool) async throws -> Data {
        let clock = ContinuousClock()
        guard let endpoint = request.url, clock.now < deadline,
              request.value(forHTTPHeaderField: "Cookie") == nil,
              request.value(forHTTPHeaderField: "Origin") == nil else { throw IssuerPhoneError.expired }
        return try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask { [session] in
                let (bytes, raw) = try await session.bytes(for: request)
                guard let response = raw as? HTTPURLResponse, response.url == endpoint, response.statusCode == 200,
                      response.value(forHTTPHeaderField: "Content-Type")?.lowercased() == "application/json",
                      response.value(forHTTPHeaderField: "Set-Cookie") == nil,
                      response.value(forHTTPHeaderField: "Content-Encoding") == nil,
                      response.expectedContentLength <= IssuerNativeSessionWire.maximumBytes,
                      !requireNoStore || response.value(forHTTPHeaderField: "Cache-Control")?.lowercased().split(separator: ",").contains(where: { $0.trimmingCharacters(in: .whitespaces) == "no-store" }) == true else { throw IssuerPhoneError.unavailable }
                var result = Data()
                for try await byte in bytes {
                    try Task.checkCancellation()
                    guard clock.now < deadline, result.count < IssuerNativeSessionWire.maximumBytes else { throw IssuerPhoneError.bound }
                    result.append(byte)
                }
                guard !result.isEmpty, clock.now < deadline else { throw IssuerPhoneError.expired }
                return result
            }
            group.addTask { try await clock.sleep(until: deadline); throw IssuerPhoneError.expired }
            defer { group.cancelAll() }
            guard let result = try await group.next() else { throw IssuerPhoneError.unavailable }; return result
        }
    }
    deinit { session.invalidateAndCancel() }
}
#endif
