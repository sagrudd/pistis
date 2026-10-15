import Foundation
import PistisCore

#if canImport(Security)
/// One configured origin, the existing exact Monas trust policy, no discovery,
/// redirect, alternate-origin retry, cookie store, cache or new authentication.
final class IssuerSiteRootTransport: @unchecked Sendable {
    private let origin: URL
    private let session: URLSession
    #if canImport(LocalAuthentication) && canImport(UIKit)
    private let nativeSession: IssuerNativeCurrentSession?
    #endif

    init(configuration: MonasSiteRootAuthorityConfiguration) throws {
        #if canImport(LocalAuthentication) && canImport(UIKit)
        nativeSession = nil
        #endif
        origin = configuration.authorityOrigin
        let settings = URLSessionConfiguration.ephemeral
        settings.httpShouldSetCookies = false
        settings.httpCookieStorage = nil
        settings.urlCache = nil
        settings.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(configuration: settings,
            delegate: try PinnedEnrolmentSessionDelegate(origin: origin, trustPolicy: configuration.trustPolicy),
            delegateQueue: nil)
    }

    // A test transport can inspect requests without TLS or key effects. This
    // does not construct a prepared owner handoff or any signing capability.
    init(origin: URL, session: URLSession) throws {
        guard MonasSiteRootDelegationTransport.isValidOrigin(origin) else {
            throw IssuerPhoneError.binding
        }
        #if canImport(LocalAuthentication) && canImport(UIKit)
        nativeSession = nil
        #endif
        self.origin = origin
        self.session = session
    }

    #if canImport(LocalAuthentication) && canImport(UIKit)
    /// Actual native authentication factory. No caller supplies a cookie/token.
    @MainActor
    static func authenticatedNative() async throws -> IssuerSiteRootTransport {
        let current = try await IssuerNativeCurrentSession.authenticateCurrent()
        return try IssuerSiteRootTransport(current: current)
    }
    @MainActor
    static func authenticatedACKNative() async throws -> (IssuerSiteRootTransport, AuthenticatedEnrollmentOutput) {
        let current = try await IssuerNativeCurrentSession.authenticateCurrent()
        return (try IssuerSiteRootTransport(current: current), current.enrollment)
    }
    @MainActor
    private init(current: IssuerNativeCurrentSession) throws {
        let enrollment = current.enrollment
        guard let enrolledOrigin = URL(string: enrollment.httpsOrigin),
              let host = CanonicalHTTPSHost.from(enrolledOrigin), enrollment.allowedHosts.contains(host)
        else { throw IssuerPhoneError.binding }
        origin = enrolledOrigin; nativeSession = current
        let settings = URLSessionConfiguration.ephemeral
        settings.httpShouldSetCookies = false; settings.httpCookieStorage = nil
        settings.urlCache = nil; settings.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(configuration: settings, delegate: try PinnedEnrolmentSessionDelegate(
            origin: enrolledOrigin, expectedSPKISHA256: enrollment.tlsSPKISHA256), delegateQueue: nil)
    }
    #endif

    func readiness(_ body: Data, deadline: ContinuousClock.Instant) async throws -> Data {
        try await post(body, path: IssuerPhoneWire.readinessPath, deadline: deadline)
    }
    func exchange(_ body: Data, deadline: ContinuousClock.Instant) async throws -> Data {
        try await post(body, path: IssuerPhoneWire.exchangePath, deadline: deadline)
    }
    func prepareACK(_ body: Data, deadline: ContinuousClock.Instant) async throws -> Data {
        try await post(body, path: ExactSourceACKWire.preparePath, deadline: deadline)
    }
    func submitACK(_ body: Data, deadline: ContinuousClock.Instant) async throws -> Data {
        try await post(body, path: ExactSourceACKWire.submitPath, deadline: deadline)
    }
    private func post(_ body: Data, path: String, deadline: ContinuousClock.Instant) async throws -> Data {
        let clock = ContinuousClock()
        guard !body.isEmpty, body.count <= 262_144, clock.now < deadline,
              let endpoint = URL(string: path, relativeTo: origin)?.absoluteURL,
              MonasSiteRootDelegationTransport.matchesAuthority(endpoint, origin: origin, expectedPath: path)
        else { throw IssuerPhoneError.expired }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = body
        request.httpShouldHandleCookies = false
        let remaining = clock.now.duration(to: deadline).components
        request.timeoutInterval = Double(remaining.seconds) + Double(remaining.attoseconds) / 1e18
        request.setValue("application/cbor", forHTTPHeaderField: "Content-Type")
        request.setValue("application/cbor", forHTTPHeaderField: "Accept")
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        var fixedRequest = request
        #if canImport(LocalAuthentication) && canImport(UIKit)
        if let nativeSession { fixedRequest = try await nativeSession.authorizedIssuerRequest(request, deadline: deadline) }
        #endif
        let authorizedRequest = fixedRequest
        do {
            return try await withThrowingTaskGroup(of: Data.self) { group in
                group.addTask { [session] in
                    let (bytes, raw) = try await session.bytes(for: authorizedRequest)
                    guard let response = raw as? HTTPURLResponse, response.url == endpoint,
                          response.statusCode == 200,
                          response.value(forHTTPHeaderField: "Content-Type")?.lowercased() == "application/cbor",
                          response.value(forHTTPHeaderField: "Content-Encoding") == nil,
                          response.value(forHTTPHeaderField: "Set-Cookie") == nil,
                          response.value(forHTTPHeaderField: "Cache-Control")?.lowercased().split(separator: ",").contains(where: { $0.trimmingCharacters(in: .whitespaces) == "no-store" }) == true,
                          response.expectedContentLength <= 262_144
                    else { throw IssuerPhoneError.unavailable }
                    var data = Data()
                    for try await byte in bytes {
                        guard clock.now < deadline, data.count < 262_144 else { throw IssuerPhoneError.bound }
                        data.append(byte)
                    }
                    guard !data.isEmpty, clock.now < deadline else { throw IssuerPhoneError.expired }
                    return data
                }
                group.addTask {
                    try await clock.sleep(until: deadline)
                    throw IssuerPhoneError.expired
                }
                defer { group.cancelAll() }
                guard let result = try await group.next() else { throw IssuerPhoneError.unavailable }
                return result
            }
        } catch {
            #if canImport(LocalAuthentication) && canImport(UIKit)
            if let nativeSession { await nativeSession.invalidate() }
            #endif
            throw error
        }
    }

    deinit { session.invalidateAndCancel() }
}
#endif
