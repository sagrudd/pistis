import Foundation

/// The only currently documented Monas Site Root endpoints.
///
/// The readiness endpoint is present to report a deliberately unavailable
/// authority. The submission endpoint accepts a signed iPhone proof and, only
/// on a successful proof consumption, returns the one-use App Attest bootstrap.
/// This client never substitutes another origin or endpoint.
enum MonasSiteRootDelegationEndpointV1 {
    static let readinessPath = "/auth/pistis/v1/site-root-delegation/readiness"
    static let submitPath = "/auth/pistis/site-root-delegations/v1/submit"
    static let installationStatusPath = "/auth/pistis/site-root-genesis/v1/installation-status"
}

struct MonasSiteRootInstallationStatusV1: Sendable {
    let redactedReference: String
    let registeredAt: Date
}

enum MonasSiteRootDelegationReadinessStateV1: String, Decodable, Equatable, Sendable {
    case ready
    case notReady = "not-ready"
}

/// Coarse, public-only Site Root authority readiness.
struct MonasSiteRootDelegationReadinessV1: Equatable, Sendable {
    let state: MonasSiteRootDelegationReadinessStateV1
    let liveCeremony: Bool
    let registeredDevice: Bool
    let appAttestBindingPresent: Bool

    /// A ceremony can proceed only when Monas explicitly reports every
    /// independently observable prerequisite.  Unknown JSON is never treated
    /// as readiness.
    var acceptsSubmission: Bool {
        state == .ready && liveCeremony && registeredDevice && appAttestBindingPresent
    }
}

protocol MonasSiteRootDelegationReadinessChecking: Sendable {
    func readiness() async throws -> MonasSiteRootDelegationReadinessV1
}

/// HTTPS-only Monas Site Root transport.
///
/// The configured origins are enrolment/trust input, never QR input.  A QR
/// submission URL must exactly match one of those origins and the reviewed v1
/// path. Redirects, cookies, caches, unexpected JSON and all non-success
/// statuses deny without selecting an unpinned endpoint.
struct MonasSiteRootDelegationTransport: MonasSiteRootCeremonyTransport,
    MonasSiteRootDelegationReadinessChecking, Sendable
{
    private enum OriginAttemptFailure: Error {
        case unreachable
        case rejected(PlatformFailure)
    }

    private static let maximumResponseBytes = 1_024
    private static let maximumSubmissionBytes = 90_000

    private let authorityOrigins: [URL]
    private let trustPolicy: MonasServerTrustPolicy
    private let session: URLSession

    private var authorityOrigin: URL { authorityOrigins[0] }
    var genesisAuthorityOrigin: URL? { authorityOrigin }
    var genesisAuthorityOrigins: [URL] { authorityOrigins }
    var authorityHost: String? { authorityOrigin.host }

    /// Returns true only for a host explicitly committed by the app build.
    /// This lets one physical computer move between its two pinned addresses
    /// without treating a selected installation's alias as a new authority.
    func isConfiguredAuthorityHost(_ host: String) -> Bool {
        guard let canonical = try? IncompleteSiteRootInstallation.canonicalHost(host)
        else { return false }
        return authorityOrigins.contains { $0.host?.lowercased() == canonical }
    }

    enum AuthorityCustodyStatusV2: Equatable {
        case appAttestAssertionRequired
        case initialRotationRequired
        case recoveryRequired
        case ready
    }

    init(
        authorityOrigin: URL,
        expectedSPKISHA256: Data,
        configuration: URLSessionConfiguration = .ephemeral
    ) throws {
        guard expectedSPKISHA256.count == 32,
              !expectedSPKISHA256.allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.invalidConfiguration }
        try self.init(
            authorityOrigins: [authorityOrigin],
            trustPolicy: .bootstrapLeafSPKI(expectedSPKISHA256),
            configuration: configuration
        )
    }

    init(
        authorityOrigin: URL,
        trustPolicy: MonasServerTrustPolicy,
        configuration: URLSessionConfiguration = .ephemeral
    ) throws {
        try self.init(
            authorityOrigins: [authorityOrigin],
            trustPolicy: trustPolicy,
            configuration: configuration
        )
    }

    init(
        authorityOrigins: [URL],
        trustPolicy: MonasServerTrustPolicy,
        configuration: URLSessionConfiguration = .ephemeral
    ) throws {
        guard !authorityOrigins.isEmpty,
              authorityOrigins.count <= 4,
              authorityOrigins.allSatisfy(Self.isValidOrigin),
              Set(authorityOrigins.map(\.absoluteString)).count == authorityOrigins.count
        else {
            throw PlatformFailure.invalidConfiguration
        }
        self.authorityOrigins = authorityOrigins
        self.trustPolicy = trustPolicy
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        self.session = URLSession(
            configuration: configuration,
            delegate: try PinnedEnrolmentSessionDelegate(
                origins: authorityOrigins,
                trustPolicy: trustPolicy
            ),
            delegateQueue: nil
        )
    }

    func appAttestTransport(authorityHost: String? = nil) throws -> MonasAppAttestTransport {
        try MonasAppAttestTransport(
            authorityOrigin: try endpointOrigin(for: authorityHost),
            authorityOrigins: authorityOrigins,
            trustPolicy: trustPolicy
        )
    }

    func siteRootConvergenceTransport(authorityHost: String? = nil) throws
        -> MonasSiteRootConvergenceTransport
    {
        try MonasSiteRootConvergenceTransport(
            authorityOrigin: try endpointOrigin(for: authorityHost),
            trustPolicy: trustPolicy
        )
    }

    /// Creates the relocation transport for the proposal-derived target while
    /// preserving this installation's authenticated Site-root trust policy.
    /// It never copies the obsolete source leaf pin to a different origin.
    func siteOriginRelocationTransport(
        targetOrigin: URL
    ) throws -> MonasSiteOriginRelocationTransportV1 {
        guard case .siteRootGeneration = trustPolicy else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        return try MonasSiteOriginRelocationTransportV1(
            targetOrigin: targetOrigin, trustPolicy: trustPolicy
        )
    }

    func readiness() async throws -> MonasSiteRootDelegationReadinessV1 {
        let endpoint = try endpoint(path: MonasSiteRootDelegationEndpointV1.readinessPath)
        var lastFailure = PlatformFailure.siteRootAuthorityUnavailable
        for candidate in candidateEndpoints(
            endpoint,
            expectedPath: MonasSiteRootDelegationEndpointV1.readinessPath
        ) {
            var request = URLRequest(url: candidate)
            request.httpMethod = "GET"
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
            request.timeoutInterval = 15
            do {
                let (data, _) = try await requestData(request, expectedURL: candidate)
                return try JSONDecoder().decode(MonasReadinessResponse.self, from: data).value
            } catch OriginAttemptFailure.unreachable {
                lastFailure = .siteRootAuthorityUnavailable
            } catch OriginAttemptFailure.rejected(let failure) {
                throw failure
            } catch let failure as PlatformFailure {
                throw failure
            } catch {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
        }
        throw lastFailure
    }

    func authorityCustodyStatusV2(authorityHost: String? = nil) async throws
        -> AuthorityCustodyStatusV2
    {
        let path = "/v1/pistis/site-trust/authority-custody/v2/status"
        let endpoint = try endpoint(
            path: path,
            authorityHost: authorityHost
        )
        var lastFailure = PlatformFailure.siteRootAuthorityUnavailable
        for candidate in candidateEndpoints(endpoint, expectedPath: path) {
            var request = URLRequest(url: candidate)
            request.httpMethod = "GET"
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
            request.timeoutInterval = 15
            do {
                let (data, response) = try await originData(for: request)
                guard let http = response as? HTTPURLResponse,
                      http.url == candidate,
                      data.count <= 1_024,
                      http.value(forHTTPHeaderField: "Cache-Control")?
                        .lowercased().contains("no-store") == true
                else { throw PlatformFailure.siteRootAuthorityUnavailable }
                if http.statusCode == 503, data.isEmpty {
                    return .appAttestAssertionRequired
                }
                guard http.statusCode == 200 else {
                    throw PlatformFailure.siteRootAuthorityUnavailable
                }
                guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      Set(object.keys) == ["schema", "state"],
                      object["schema"] as? String == "monas.first-authority-custody-status.v2",
                      let state = object["state"] as? String
                else { throw PlatformFailure.siteRootAuthorityUnavailable }
                switch state {
                case "initial-rotation-required": return .initialRotationRequired
                case "recovery-required": return .recoveryRequired
                case "ready": return .ready
                default: throw PlatformFailure.siteRootAuthorityUnavailable
                }
            } catch OriginAttemptFailure.unreachable {
                lastFailure = .siteRootAuthorityUnavailable
            } catch OriginAttemptFailure.rejected(let failure) {
                throw failure
            } catch let failure as PlatformFailure {
                throw failure
            } catch {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
        }
        throw lastFailure
    }

    /// Reads only a matching, already proof-consumed Site Root lifecycle
    /// record. This is display reconciliation, never session or authority.
    func installationStatus(
        siteRootDeviceKeyID: String,
        authorityHost: String? = nil
    ) async throws -> MonasSiteRootInstallationStatusV1? {
        guard !siteRootDeviceKeyID.isEmpty,
              siteRootDeviceKeyID.utf8.count <= 128,
              siteRootDeviceKeyID.utf8.allSatisfy({
                  ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                      || ($0 >= 97 && $0 <= 122) || [45, 46, 58, 95].contains($0)
              })
        else { throw PlatformFailure.invalidConfiguration }
        let endpoint = try endpoint(
            path: MonasSiteRootDelegationEndpointV1.installationStatusPath,
            authorityHost: authorityHost
        )
        var lastFailure = PlatformFailure.siteRootAuthorityUnavailable
        for candidate in candidateEndpoints(
            endpoint,
            expectedPath: MonasSiteRootDelegationEndpointV1.installationStatusPath
        ) {
            var request = URLRequest(url: candidate)
            request.httpMethod = "GET"
            request.timeoutInterval = 15
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
            request.setValue(siteRootDeviceKeyID, forHTTPHeaderField: "X-Pistis-Site-Root-Key-ID")
            do {
                let (data, response) = try await originData(for: request)
                guard let http = response as? HTTPURLResponse, http.url == candidate else {
                    throw PlatformFailure.siteRootAuthorityUnavailable
                }
                if http.statusCode == 404, data.isEmpty { return nil }
                guard http.statusCode == 200, data.count <= Self.maximumResponseBytes else {
                    throw PlatformFailure.siteRootAuthorityUnavailable
                }
                return try MonasInstallationStatusResponse(data: data).value
            } catch OriginAttemptFailure.unreachable {
                lastFailure = .siteRootAuthorityUnavailable
            } catch OriginAttemptFailure.rejected(let failure) {
                throw failure
            } catch let failure as PlatformFailure {
                throw failure
            } catch {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
        }
        throw lastFailure
    }

    /// Submits one detached iPhone proof and accepts only the exact bootstrap
    /// response defined by Monas. The bootstrap remains a stack-local value and
    /// must immediately construct the separately pinned App Attest transport.
    /// This method deliberately rejects the static initial-ceremony response:
    /// accepting that response here would silently downgrade a live App Attest
    /// ceremony into a proof-only completion.
    func submit(_ request: MonasSiteRootDelegationSubmissionRequestV1) async throws
        -> MonasAppAttestCeremonyBootstrap
    {
        guard Self.matchesAuthority(
            request.endpoint,
            origins: authorityOrigins,
            expectedPath: MonasSiteRootDelegationEndpointV1.submitPath
        ) else { throw PlatformFailure.siteRootAuthorityUnavailable }

        let body: Data
        do {
            body = try JSONEncoder().encode(MonasSubmissionRequest(request.submission))
        } catch {
            throw PlatformFailure.invalidConfiguration
        }
        guard body.count <= Self.maximumSubmissionBytes else {
            throw PlatformFailure.invalidConfiguration
        }
        guard let nowUnixMillis = Self.nowUnixMillis() else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        var lastFailure = PlatformFailure.siteRootAuthorityUnavailable
        for endpoint in candidateEndpoints(
            request.endpoint,
            expectedPath: MonasSiteRootDelegationEndpointV1.submitPath
        ) {
            var urlRequest = URLRequest(url: endpoint)
            urlRequest.httpMethod = "POST"
            urlRequest.httpBody = body
            urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
            urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
            urlRequest.setValue("no-store", forHTTPHeaderField: "Cache-Control")
            urlRequest.timeoutInterval = 15
            do {
                let (data, _) = try await requestData(
                    urlRequest,
                    expectedURL: endpoint,
                    expectedStatus: 200
                )
                return try MonasAppAttestBootstrapResponse(
                    data: data,
                    authorityOrigins: authorityOrigins,
                    nowUnixMillis: nowUnixMillis
                ).bootstrap
            } catch OriginAttemptFailure.unreachable {
                lastFailure = .siteRootAuthorityUnavailable
            } catch OriginAttemptFailure.rejected(let failure) {
                throw failure
            } catch let failure as PlatformFailure {
                throw failure
            } catch {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
        }
        throw lastFailure
    }

    /// Completes only the attended, first-device static Site Root ceremony.
    ///
    /// The fixed initial Monas route returns an empty ``204 No Content`` only
    /// after it has atomically consumed the signed Site Root proof and created
    /// the Site Trust authority/custody record.  This is not a bootstrap and
    /// cannot start App Attest; it records an incomplete installation for the
    /// later protected App Attest session ceremony. Any body, alternate 2xx
    /// response, redirect, cookie or endpoint mismatch is terminal.
    func submitInitialStaticCompletion(
        _ request: MonasSiteRootDelegationSubmissionRequestV1
    ) async throws {
        guard Self.matchesAuthority(
            request.endpoint,
            origins: authorityOrigins,
            expectedPath: MonasSiteRootDelegationEndpointV1.submitPath
        ) else { throw PlatformFailure.siteRootAuthorityUnavailable }

        let body: Data
        do {
            body = try JSONEncoder().encode(MonasSubmissionRequest(request.submission))
        } catch {
            throw PlatformFailure.invalidConfiguration
        }
        guard body.count <= Self.maximumSubmissionBytes else {
            throw PlatformFailure.invalidConfiguration
        }
        var lastFailure = PlatformFailure.siteRootAuthorityUnavailable
        for endpoint in candidateEndpoints(
            request.endpoint,
            expectedPath: MonasSiteRootDelegationEndpointV1.submitPath
        ) {
            var urlRequest = URLRequest(url: endpoint)
            urlRequest.httpMethod = "POST"
            urlRequest.httpBody = body
            urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
            urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
            urlRequest.setValue("no-store", forHTTPHeaderField: "Cache-Control")
            urlRequest.timeoutInterval = 15
            do {
                let (data, response) = try await session.data(for: urlRequest)
                guard let http = response as? HTTPURLResponse,
                      http.statusCode == 204,
                      http.url == endpoint,
                      data.isEmpty,
                      http.value(forHTTPHeaderField: "Set-Cookie") == nil
                else { throw PlatformFailure.siteRootAuthorityUnavailable }
                return
            } catch OriginAttemptFailure.unreachable {
                lastFailure = .siteRootAuthorityUnavailable
            } catch OriginAttemptFailure.rejected(let failure) {
                throw failure
            } catch let failure as PlatformFailure {
                throw failure
            } catch {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
        }
        throw lastFailure
    }

    /// Posts the sole public first-device registration to the fixed, pinned
    /// authority. The response may contain only the issued one-time canonical
    /// delegation and its binding facts; it cannot select a new endpoint.
    func registerGenesis(
        _ request: SiteRootGenesisRegistrationRequestV1,
        progress: @escaping @Sendable (SiteRootGenesisRegistrationProgressV1) -> Void
    ) async throws
        -> SiteRootDelegationPresentationV1
    {
        guard Self.matchesAuthority(
            request.presentation.registrationURL,
            origins: authorityOrigins,
            expectedPath: MonasSiteRootGenesisEndpointV1.registrationPath
        ) else { throw PlatformFailure.siteRootAuthorityUnavailable }
        let body: Data
        do {
            body = try JSONEncoder().encode(MonasSiteRootGenesisRegistrationRequest(request))
        } catch {
            throw PlatformFailure.invalidConfiguration
        }
        guard !body.isEmpty, body.count <= Self.maximumSubmissionBytes else {
            throw PlatformFailure.invalidConfiguration
        }
        var lastFailure = PlatformFailure.siteRootAuthorityUnavailable
        for endpoint in candidateEndpoints(
            request.presentation.registrationURL,
            expectedPath: MonasSiteRootGenesisEndpointV1.registrationPath
        ) {
            var urlRequest = URLRequest(url: endpoint)
            urlRequest.httpMethod = "POST"
            urlRequest.httpBody = body
            urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
            urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
            urlRequest.setValue("no-store", forHTTPHeaderField: "Cache-Control")
            urlRequest.timeoutInterval = 15
            do {
                let (data, _) = try await requestData(
                    urlRequest,
                    expectedURL: endpoint,
                    expectedStatus: 200,
                    maximumResponseBytes: Self.maximumSubmissionBytes
                )
                let delegation = try MonasSiteRootGenesisRegistrationResult(
                    data: data,
                    request: request,
                    authorityOrigins: authorityOrigins
                ).presentation
                progress(.registrationAccepted)
                progress(.delegationReady)
                return delegation
            } catch OriginAttemptFailure.unreachable {
                lastFailure = .siteRootAuthorityUnavailable
            } catch OriginAttemptFailure.rejected(let failure) {
                throw failure
            } catch let failure as PlatformFailure {
                throw failure
            } catch {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
        }
        throw lastFailure
    }

    private func endpoint(path: String, authorityHost: String? = nil) throws -> URL {
        let origin = try endpointOrigin(for: authorityHost)
        guard let endpoint = URL(string: path, relativeTo: origin)?.absoluteURL,
              Self.matchesAuthority(endpoint, origin: origin, expectedPath: path)
        else { throw PlatformFailure.invalidConfiguration }
        return endpoint
    }

    private func endpointOrigin(for host: String?) throws -> URL {
        guard let host else { return authorityOrigin }
        guard let origin = authorityOrigins.first(where: {
            $0.host?.lowercased() == (try? IncompleteSiteRootInstallation.canonicalHost(host))
        }) else { throw PlatformFailure.siteRootAuthorityUnavailable }
        return origin
    }

    /// Returns the signed endpoint first, followed only by the other origins
    /// committed in this build. The request body is byte-identical for every
    /// candidate; no QR value or endpoint outside the pinned set is accepted.
    private func candidateEndpoints(_ endpoint: URL, expectedPath: String) -> [URL] {
        guard Self.matchesAuthority(endpoint, origins: authorityOrigins, expectedPath: expectedPath)
        else { return [] }
        var candidates = [endpoint]
        for origin in authorityOrigins {
            guard origin.host != endpoint.host || origin.port != endpoint.port,
                  let candidate = URL(string: expectedPath, relativeTo: origin)?.absoluteURL,
                  Self.matchesAuthority(candidate, origin: origin, expectedPath: expectedPath)
            else { continue }
            candidates.append(candidate)
        }
        return candidates
    }

    private func requestData(
        _ request: URLRequest,
        expectedURL: URL,
        expectedStatus: Int? = nil,
        maximumResponseBytes: Int = Self.maximumResponseBytes
    ) async throws
        -> (Data, URLResponse)
    {
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse,
                  expectedStatus.map({ http.statusCode == $0 }) ?? (200 ... 299).contains(http.statusCode),
                  http.url == expectedURL,
                  data.count <= maximumResponseBytes
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
            return (data, response)
        } catch let failure as PlatformFailure {
            throw OriginAttemptFailure.rejected(failure)
        } catch {
            if Self.isOriginUnreachable(error) {
                throw OriginAttemptFailure.unreachable
            }
            throw OriginAttemptFailure.rejected(.siteRootAuthorityUnavailable)
        }
    }

    private static func isOriginUnreachable(_ error: Error) -> Bool {
        guard let urlError = error as? URLError else { return false }
        switch urlError.code {
        case .cannotConnectToHost, .cannotFindHost, .dnsLookupFailed,
             .networkConnectionLost, .notConnectedToInternet, .resourceUnavailable,
             .timedOut:
            return true
        default:
            return false
        }
    }

    private func originData(for request: URLRequest) async throws -> (Data, URLResponse) {
        do {
            return try await session.data(for: request)
        } catch {
            if Self.isOriginUnreachable(error) {
                throw OriginAttemptFailure.unreachable
            }
            throw OriginAttemptFailure.rejected(.siteRootAuthorityUnavailable)
        }
    }

    static func isValidOrigin(_ value: URL) -> Bool {
        value.scheme == "https" && value.host != nil && value.user == nil
            && value.password == nil && value.query == nil && value.fragment == nil
            && value.path.isEmpty
    }

    static func matchesAuthority(_ value: URL, origin: URL, expectedPath: String) -> Bool {
        matchesAuthority(value, origins: [origin], expectedPath: expectedPath)
    }

    static func matchesAuthority(
        _ value: URL,
        origins: [URL],
        expectedPath: String
    ) -> Bool {
        origins.contains { origin in
            value.scheme == "https" && value.host == origin.host && value.port == origin.port
            && value.user == nil && value.password == nil && value.query == nil
            && value.fragment == nil && value.path == expectedPath
        }
    }

    private static func nowUnixMillis() -> UInt64? {
        let value = Date().timeIntervalSince1970 * 1_000
        guard value.isFinite, value >= 0, value <= Double(UInt64.max) else { return nil }
        return UInt64(value)
    }
}

struct MonasInstallationStatusResponse: Decodable {
    let schema: String
    let state: String
    let redactedReference: String
    let registeredAtUnixMillis: UInt64

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema, state
        case redactedReference = "redacted_reference"
        case registeredAtUnixMillis = "registered_at_unix_millis"
    }

    init(data: Data) throws {
        let decoder = JSONDecoder()
        let keys = try decoder.decode(StrictKeys.self, from: data)
        guard keys.values == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        let decoded = try decoder.decode(Self.self, from: data)
        self = decoded
    }

    var value: MonasSiteRootInstallationStatusV1 {
        get throws {
            guard schema == "monas.site-root-genesis-installation-status.v1",
                  ["proof-consumed", "completed"].contains(state),
                  !redactedReference.isEmpty, redactedReference.utf8.count <= 64,
                  redactedReference.unicodeScalars.allSatisfy({
                      CharacterSet.alphanumerics.contains($0)
                          || $0 == "." || $0 == "-" || $0 == "…"
                  })
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
            return MonasSiteRootInstallationStatusV1(
                redactedReference: redactedReference,
                registeredAt: Date(timeIntervalSince1970: TimeInterval(registeredAtUnixMillis) / 1_000)
            )
        }
    }

    private struct StrictKeys: Decodable {
        let values: Set<String>
        init(from decoder: any Decoder) throws {
            values = Set(try decoder.container(keyedBy: DynamicKey.self).allKeys.map(\.stringValue))
        }
    }
}

private struct DynamicKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

private struct MonasReadinessResponse: Decodable {
    let schema: String
    let state: MonasSiteRootDelegationReadinessStateV1
    let liveCeremony: Bool
    let registeredDevice: Bool
    let appAttestBindingPresent: Bool
    let reasons: [String]

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema, state, reasons
        case liveCeremony = "live_ceremony"
        case registeredDevice = "registered_device"
        case appAttestBindingPresent = "app_attest_binding_present"
    }

    init(from decoder: any Decoder) throws {
        let untyped = try decoder.container(keyedBy: MonasSiteRootWireKey.self)
        guard Set(untyped.allKeys.map(\.stringValue)) == Set(CodingKeys.allCases.map(\.rawValue)) else {
            throw DecodingError.dataCorruptedError(forKey: .schema, in: try decoder.container(keyedBy: CodingKeys.self), debugDescription: "unexpected readiness fields")
        }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        schema = try values.decode(String.self, forKey: .schema)
        state = try values.decode(MonasSiteRootDelegationReadinessStateV1.self, forKey: .state)
        liveCeremony = try values.decode(Bool.self, forKey: .liveCeremony)
        registeredDevice = try values.decode(Bool.self, forKey: .registeredDevice)
        appAttestBindingPresent = try values.decode(Bool.self, forKey: .appAttestBindingPresent)
        reasons = try values.decode([String].self, forKey: .reasons)
        guard schema == "monas.site-root-delegation-readiness.v1", reasons.count <= 8,
              reasons.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 96 })
        else { throw DecodingError.dataCorruptedError(forKey: .schema, in: values, debugDescription: "invalid readiness response") }
    }

    var value: MonasSiteRootDelegationReadinessV1 {
        .init(state: state, liveCeremony: liveCeremony, registeredDevice: registeredDevice, appAttestBindingPresent: appAttestBindingPresent)
    }
}

private struct MonasSubmissionRequest: Encodable {
    let schema: String
    let reference: String
    let delegation: JSONValue
    let coseSign1Base64URL: String

    enum CodingKeys: String, CodingKey { case schema, reference, delegation, coseSign1Base64URL = "cose_sign1_base64url" }

    init(_ submission: SiteRootDelegationSubmissionV1) throws {
        schema = submission.schema
        reference = submission.reference
        delegation = try JSONDecoder().decode(JSONValue.self, from: submission.canonicalDelegationJSON)
        coseSign1Base64URL = submission.coseSign1Base64URL
    }
}

/// Strict, redacted bootstrap response issued only after Monas atomically
/// consumes the signed Site Root proof. It deliberately has no persistence or
/// public initializer: callers can obtain the typed value only from the exact
/// HTTPS response decoder below.
private struct MonasAppAttestBootstrapResponse {
    private static let schema = "monas.pistis.site-trust-app-attest-bootstrap.v1"
    private static let maximumLifetimeMillis: UInt64 = 300_000

    let bootstrap: MonasAppAttestCeremonyBootstrap

    init(data: Data, authorityOrigin: URL, nowUnixMillis: UInt64) throws {
        try self.init(
            data: data,
            authorityOrigins: [authorityOrigin],
            nowUnixMillis: nowUnixMillis
        )
    }

    init(data: Data, authorityOrigins: [URL], nowUnixMillis: UInt64) throws {
        let decoder = JSONDecoder()
        let response: WireResponse
        do {
            response = try decoder.decode(WireResponse.self, from: data)
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        guard response.schema == Self.schema,
              let origin = URL(string: response.httpsOrigin),
              MonasSiteRootDelegationTransport.isValidOrigin(origin),
              response.httpsOrigin == origin.absoluteString,
              authorityOrigins.contains(where: {
                  origin.absoluteString == $0.absoluteString
              }),
              let spki = Self.decodeCanonicalBase64URL(
                  response.tlsSPKISHA256B64URL,
                  exactLength: 32
              ),
              let ceremonyID = Self.decodeCanonicalBase64URL(
                  response.ceremonyIDB64URL,
                  exactLength: 16
              ),
              let challenge = Self.decodeCanonicalBase64URL(
                  response.challengeDigestB64URL,
                  exactLength: 32
              ),
              response.expiresAtUnixMillis > nowUnixMillis,
              response.expiresAtUnixMillis - nowUnixMillis <= Self.maximumLifetimeMillis
        else { throw PlatformFailure.siteRootAuthorityUnavailable }

        do {
            bootstrap = try MonasAppAttestCeremonyBootstrap(
                httpsOrigin: origin,
                tlsSPKISHA256: spki,
                ceremonyID: ceremonyID,
                challengeDigest: challenge
            )
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
    }

    private struct WireResponse: Decodable {
        let schema: String
        let httpsOrigin: String
        let tlsSPKISHA256B64URL: String
        let ceremonyIDB64URL: String
        let challengeDigestB64URL: String
        let expiresAtUnixMillis: UInt64

        private enum CodingKeys: String, CodingKey, CaseIterable {
            case schema
            case httpsOrigin = "https_origin"
            case tlsSPKISHA256B64URL = "tls_spki_sha256_b64url"
            case ceremonyIDB64URL = "ceremony_id_b64url"
            case challengeDigestB64URL = "challenge_digest_b64url"
            case expiresAtUnixMillis = "expires_at_unix_millis"
        }

        init(from decoder: any Decoder) throws {
            let untyped = try decoder.container(keyedBy: MonasSiteRootWireKey.self)
            guard Set(untyped.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue))
            else {
                throw DecodingError.dataCorruptedError(
                    forKey: .schema,
                    in: try decoder.container(keyedBy: CodingKeys.self),
                    debugDescription: "unexpected bootstrap fields"
                )
            }
            let values = try decoder.container(keyedBy: CodingKeys.self)
            schema = try values.decode(String.self, forKey: .schema)
            httpsOrigin = try values.decode(String.self, forKey: .httpsOrigin)
            tlsSPKISHA256B64URL = try values.decode(String.self, forKey: .tlsSPKISHA256B64URL)
            ceremonyIDB64URL = try values.decode(String.self, forKey: .ceremonyIDB64URL)
            challengeDigestB64URL = try values.decode(String.self, forKey: .challengeDigestB64URL)
            expiresAtUnixMillis = try values.decode(UInt64.self, forKey: .expiresAtUnixMillis)
        }
    }

    private static func decodeCanonicalBase64URL(_ value: String, exactLength: Int) -> Data? {
        guard !value.isEmpty,
              value.utf8.allSatisfy({ byte in
                  (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
                      || (byte >= 48 && byte <= 57) || byte == 45 || byte == 95
              }),
              value.count % 4 != 1
        else { return nil }
        let padding = String(repeating: "=", count: (4 - value.count % 4) % 4)
        let standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + padding
        guard let decoded = Data(base64Encoded: standard),
              decoded.count == exactLength,
              !decoded.allSatisfy({ $0 == 0 }),
              decoded.base64EncodedString()
                  .replacingOccurrences(of: "+", with: "-")
                  .replacingOccurrences(of: "/", with: "_")
                  .replacingOccurrences(of: "=", with: "") == value
        else { return nil }
        return decoded
    }
}

/// Fixed-origin, host-agnostic transport for a fresh-device Site Root
/// genesis. It relays the existing Monas genesis registration and static
/// completion protocols through the install broker while refusing to use any
/// host or endpoint supplied by QR data.
struct MonasSiteRootGenesisBrokerTransport: MonasSiteRootCeremonyTransport,
    Sendable
{
    private let brokerOrigin: URL
    private let session: URLSession
    private let maximumPollAttempts: Int
    private let pollDelayNanoseconds: UInt64
    private let maximumPollDuration: TimeInterval

    var genesisAuthorityOrigin: URL? { brokerOrigin }
    var requiresGenesisCorrelation: Bool { true }

    init() throws {
        guard let origin = URL(string: MonasSiteRootGenesisBrokerEndpointV1.origin),
              MonasSiteRootDelegationTransport.isValidOrigin(origin)
        else { throw PlatformFailure.invalidConfiguration }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(
            configuration: configuration,
            delegate: RedirectRejectingSessionDelegate(),
            delegateQueue: nil
        )
        try self.init(session: session)
    }

    init(
        session: URLSession,
        maximumPollAttempts: Int = MonasSiteRootGenesisBrokerEndpointV1.maximumPollAttempts,
        pollDelayNanoseconds: UInt64 = 100_000_000,
        maximumPollDuration: TimeInterval = MonasSiteRootGenesisBrokerEndpointV1.maximumPollDurationSeconds
    ) throws {
        guard let origin = URL(string: MonasSiteRootGenesisBrokerEndpointV1.origin),
              MonasSiteRootDelegationTransport.isValidOrigin(origin),
              maximumPollAttempts > 0,
              maximumPollDuration > 0
        else { throw PlatformFailure.invalidConfiguration }
        brokerOrigin = origin
        self.session = session
        self.maximumPollAttempts = maximumPollAttempts
        self.pollDelayNanoseconds = pollDelayNanoseconds
        self.maximumPollDuration = maximumPollDuration
    }

    func registerGenesis(
        _ request: SiteRootGenesisRegistrationRequestV1,
        progress: @escaping @Sendable (SiteRootGenesisRegistrationProgressV1) -> Void
    ) async throws
        -> SiteRootDelegationPresentationV1
    {
        guard let correlation = request.presentation.correlation,
              Self.validCorrelation(correlation),
              Self.matchesFixedEndpoint(
                  request.presentation.registrationURL,
                  path: MonasSiteRootGenesisBrokerEndpointV1.registrationPath
              )
        else { throw PlatformFailure.siteRootGenesisRegistrationRejected }

        let body: Data
        do {
            body = try JSONEncoder().encode(
                try MonasSiteRootGenesisBrokerRegistrationRequest(request)
            )
        } catch {
            throw PlatformFailure.invalidConfiguration
        }
        guard !body.isEmpty,
              body.count <= MonasSiteRootGenesisBrokerEndpointV1.maximumRegistrationBytes
        else {
            throw PlatformFailure.invalidConfiguration
        }
        let endpoint = try fixedEndpoint(MonasSiteRootGenesisBrokerEndpointV1.registrationPath)
        let data = try await post(
            body: body,
            endpoint: endpoint,
            expectedStatus: 202,
            maximumResponseBytes: 1_024,
            rejection: .siteRootGenesisRegistrationRejected
        )
        try Self.decodeAcceptedRegistrationResponse(data)
        progress(.registrationAccepted)
        let proofURL = try fixedEndpoint(MonasSiteRootGenesisBrokerEndpointV1.proofPath)
        let deadline = Date().addingTimeInterval(maximumPollDuration)
        progress(.delegationPollStarted)

        for attempt in 0..<maximumPollAttempts {
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else {
                throw PlatformFailure.siteRootGenesisDelegationTimedOut
            }
            let pollBody = try JSONEncoder().encode(
                MonasSiteRootGenesisBrokerDelegationPollRequest(correlation: correlation)
            )
            let pollData = try await post(
                body: pollBody,
                endpoint: try fixedEndpoint(
                    MonasSiteRootGenesisBrokerEndpointV1.delegationPollPath
                ),
                expectedStatus: 200,
                maximumResponseBytes: MonasSiteRootGenesisBrokerEndpointV1.maximumDelegationBytes,
                timeoutInterval: min(15, remaining),
                rejection: .siteRootGenesisDelegationUnavailable
            )
            switch try Self.decodeDelegationPollResponse(pollData) {
            case .ready(let delegationData):
                let delegation = try MonasSiteRootGenesisRegistrationResult(
                    brokerData: delegationData,
                    request: request,
                    brokerProofURL: proofURL,
                    correlation: correlation
                ).presentation
                progress(.delegationReady)
                return delegation
            case .pending:
                if attempt + 1 < maximumPollAttempts {
                    let remaining = deadline.timeIntervalSinceNow
                    guard remaining > 0 else {
                        throw PlatformFailure.siteRootGenesisDelegationTimedOut
                    }
                    try await Task.sleep(
                        nanoseconds: min(
                            pollDelayNanoseconds,
                            UInt64(remaining * 1_000_000_000)
                        )
                    )
                }
            }
        }
        throw PlatformFailure.siteRootGenesisDelegationTimedOut
    }

    /// The normal App Attest bootstrap submission is an enrolled-authority
    /// operation and is deliberately unavailable on the pre-authority broker.
    func submit(_: MonasSiteRootDelegationSubmissionRequestV1) async throws
        -> MonasAppAttestCeremonyBootstrap
    {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }

    func submitInitialStaticCompletion(
        _ request: MonasSiteRootDelegationSubmissionRequestV1
    ) async throws {
        guard let correlation = request.submission.correlation,
              Self.validCorrelation(correlation),
              Self.matchesFixedEndpoint(
                  request.endpoint,
                  path: MonasSiteRootGenesisBrokerEndpointV1.proofPath
              )
        else { throw PlatformFailure.siteRootGenesisCompletionRejected }

        let body: Data
        do {
            body = try JSONEncoder().encode(
                MonasSiteRootGenesisBrokerProofRequest(
                    request.submission, correlation: correlation
                )
            )
        } catch {
            throw PlatformFailure.invalidConfiguration
        }
        guard !body.isEmpty,
              body.count <= MonasSiteRootGenesisBrokerEndpointV1.maximumProofBytes
        else {
            throw PlatformFailure.invalidConfiguration
        }
        let endpoint = try fixedEndpoint(MonasSiteRootGenesisBrokerEndpointV1.proofPath)
        let data = try await post(
            body: body,
            endpoint: endpoint,
            expectedStatus: 202,
            maximumResponseBytes: 1_024,
            rejection: .siteRootGenesisCompletionRejected
        )
        do {
            let object = try StrictJSONObject(data: data, maximumBytes: 1_024).values
            guard Set(object.keys) == ["schema", "state"],
                  case let .string(schema)? = object["schema"],
                  schema == MonasSiteRootGenesisBrokerEndpointV1.responseSchema,
                  case let .string(state)? = object["state"], state == "accepted"
            else { throw PlatformFailure.siteRootGenesisCompletionRejected }
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.siteRootGenesisCompletionRejected
        }
    }

    /// Sends one redacted iPhone-side onboarding event to the fixed install
    /// broker. The correlation is the short-lived capability carried by the
    /// server-issued protected QR; it is not a host credential. Delivery is
    /// best effort and has no effect on the protected proof transaction.
    func uploadOnboardingEvent(_ event: OnboardingEvent, correlation: Data) async throws {
        guard Self.validCorrelation(correlation) else {
            throw PlatformFailure.onboardingEventUploadRejected
        }
        let eventBytes = withUnsafeBytes(of: event.id.uuid) { Data($0) }
        guard eventBytes.count == 16 else {
            throw PlatformFailure.onboardingEventUploadRejected
        }
        let body = try JSONEncoder().encode(
            MonasSiteRootGenesisDiagnosticRequest(
                event: event,
                correlation: Self.base64URL(correlation),
                eventID: Self.base64URL(eventBytes)
            )
        )
        guard body.count <= 4_096 else {
            throw PlatformFailure.onboardingEventUploadRejected
        }
        let data = try await post(
            body: body,
            endpoint: try fixedEndpoint(MonasSiteRootGenesisBrokerEndpointV1.diagnosticsPath),
            expectedStatus: 202,
            maximumResponseBytes: 1_024,
            rejection: .onboardingEventUploadRejected
        )
        do {
            let object = try StrictJSONObject(data: data, maximumBytes: 1_024).values
            guard Set(object.keys) == ["schema", "sequence", "state"],
                  case let .string(schema)? = object["schema"],
                  schema == MonasSiteRootGenesisBrokerEndpointV1.responseSchema,
                  case let .string(state)? = object["state"], state == "accepted",
                  case let .number(sequence)? = object["sequence"],
                  UInt64(sequence) == UInt64(event.sequence)
            else { throw PlatformFailure.onboardingEventUploadRejected }
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.onboardingEventUploadRejected
        }
    }

    private func fixedEndpoint(_ path: String) throws -> URL {
        guard let endpoint = URL(string: path, relativeTo: brokerOrigin)?.absoluteURL,
              Self.matchesFixedEndpoint(endpoint, path: path)
        else { throw PlatformFailure.invalidConfiguration }
        return endpoint
    }

    private func post(
        body: Data,
        endpoint: URL,
        expectedStatus: Int,
        maximumResponseBytes: Int,
        timeoutInterval: TimeInterval = 15,
        rejection: PlatformFailure
    ) async throws -> Data {
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = timeoutInterval
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        do {
            let (data, rawResponse) = try await session.data(for: request)
            guard let response = rawResponse as? HTTPURLResponse,
                  response.url == endpoint,
                  response.statusCode == expectedStatus,
                  data.count <= maximumResponseBytes,
                  response.value(forHTTPHeaderField: "Cache-Control")?
                    .lowercased().contains("no-store") == true,
                  response.value(forHTTPHeaderField: "Set-Cookie") == nil
            else { throw rejection }
            return data
        } catch let failure as PlatformFailure {
            throw failure
        } catch is CancellationError {
            throw PlatformFailure.operationCancelled
        } catch {
            throw PlatformFailure.siteRootGenesisTransportUnavailable
        }
    }

    private static func validCorrelation(_ value: Data) -> Bool {
        value.count == 32 && !value.allSatisfy({ $0 == 0 })
    }

    private static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private enum DelegationPollResponse {
        case pending
        case ready(Data)
    }

    private static func decodeAcceptedRegistrationResponse(_ data: Data) throws {
        do {
            let object = try StrictJSONObject(data: data, maximumBytes: 1_024).values
            guard Set(object.keys) == ["schema", "state"],
                  case let .string(schema)? = object["schema"],
                  schema == MonasSiteRootGenesisBrokerEndpointV1.responseSchema,
                  case let .string(state)? = object["state"], state == "accepted"
            else { throw PlatformFailure.siteRootGenesisRegistrationRejected }
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.siteRootGenesisRegistrationRejected
        }
    }

    private static func decodeDelegationPollResponse(_ data: Data) throws
        -> DelegationPollResponse
    {
        do {
            let object = try StrictJSONObject(
                data: data,
                maximumBytes: MonasSiteRootGenesisBrokerEndpointV1.maximumDelegationBytes
            ).values
            guard case let .string(schema)? = object["schema"],
                  schema == MonasSiteRootGenesisBrokerEndpointV1.responseSchema,
                  case let .string(state)? = object["state"]
            else { throw PlatformFailure.siteRootGenesisDelegationUnavailable }
            switch state {
            case "pending":
                guard Set(object.keys) == ["schema", "state"] else {
                    throw PlatformFailure.siteRootGenesisDelegationUnavailable
                }
                return .pending
            case "ready":
                guard Set(object.keys) == ["schema", "state", "delegation_b64url"],
                      case let .string(encoded)? = object["delegation_b64url"],
                      let delegation = decodeCanonicalBase64URL(encoded),
                      !delegation.isEmpty,
                      delegation.count <= MonasSiteRootGenesisBrokerEndpointV1.maximumDelegationBytes
                else { throw PlatformFailure.siteRootGenesisDelegationUnavailable }
                return .ready(delegation)
            case "expired":
                guard Set(object.keys) == ["schema", "state"] else {
                    throw PlatformFailure.siteRootGenesisDelegationUnavailable
                }
                throw PlatformFailure.siteRootGenesisDelegationExpired
            case "consumed":
                guard Set(object.keys) == ["schema", "state"] else {
                    throw PlatformFailure.siteRootGenesisDelegationUnavailable
                }
                throw PlatformFailure.siteRootGenesisDelegationConsumed
            default:
                throw PlatformFailure.siteRootGenesisDelegationUnavailable
            }
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.siteRootGenesisDelegationUnavailable
        }
    }

    private static func decodeCanonicalBase64URL(
        _ value: String,
        exactLength: Int? = nil
    ) -> Data? {
        guard !value.isEmpty,
              value.utf8.allSatisfy({
                  ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                      || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95
              }), value.count % 4 != 1
        else { return nil }
        let padding = String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let decoded = Data(base64Encoded: value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + padding),
              exactLength.map({ decoded.count == $0 }) ?? true,
              decoded.base64EncodedString()
                  .replacingOccurrences(of: "+", with: "-")
                  .replacingOccurrences(of: "/", with: "_")
                  .replacingOccurrences(of: "=", with: "") == value
        else { return nil }
        return decoded
    }

    private static func matchesFixedEndpoint(_ value: URL, path: String) -> Bool {
        guard let origin = URL(string: MonasSiteRootGenesisBrokerEndpointV1.origin) else {
            return false
        }
        return MonasSiteRootDelegationTransport.matchesAuthority(
            value, origin: origin, expectedPath: path
        )
    }
}

private struct MonasSiteRootGenesisDiagnosticRequest: Encodable {
    let schema: String
    let purpose: String
    let correlationB64URL: String
    let eventIDB64URL: String
    let sequence: UInt32
    let stage: String
    let action: String
    let outcome: String
    let elapsedMs: UInt32
    let httpStatus: UInt16
    let errorCode: String

    enum CodingKeys: String, CodingKey {
        case schema, purpose
        case correlationB64URL = "correlation_b64url"
        case eventIDB64URL = "event_id_b64url"
        case sequence, stage, action, outcome
        case elapsedMs = "elapsed_ms"
        case httpStatus = "http_status"
        case errorCode = "error_code"
    }

    init(event: OnboardingEvent, correlation: String, eventID: String) {
        schema = MonasSiteRootGenesisBrokerEndpointV1.diagnosticsSchema
        purpose = "site-root-genesis"
        correlationB64URL = correlation
        eventIDB64URL = eventID
        sequence = event.sequence
        stage = switch event.stage {
        case .qrValidation: "qr_accepted"
        case .siteRootKey: "site_root_key"
        case .appAttest: "app_attest_registration"
        case .monasDelegation: "registration_post"
        case .delegationPoll: "delegation_poll"
        case .siteRootProof: "proof_post"
        case .proofResponse: "proof_response"
        case .faceID: "face_id"
        case .providerVerification: "ceremony_complete"
        case .deviceRegistration: "site_root_key"
        }
        action = event.kind == .stageEntered && event.outcome == .started ? "start" : "response"
        outcome = switch event.outcome {
        case .started: "started"
        case .accepted, .succeeded: "accepted"
        case .rejected, .failed: "rejected"
        case .cancelled: "cancelled"
        }
        elapsedMs = event.elapsedMs
        httpStatus = event.httpStatus
        errorCode = event.failure?.rawValue ?? ""
    }
}

private struct MonasSiteRootWireKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

enum JSONValue: Codable {
    case object([String: JSONValue]), array([JSONValue]), string(String), number(Double), bool(Bool), null
    init(from decoder: any Decoder) throws {
        let single = try decoder.singleValueContainer()
        if single.decodeNil() { self = .null }
        else if let value = try? single.decode(Bool.self) { self = .bool(value) }
        else if let value = try? single.decode(Double.self) { self = .number(value) }
        else if let value = try? single.decode(String.self) { self = .string(value) }
        else if let values = try? single.decode([String: JSONValue].self) { self = .object(values) }
        else { self = .array(try single.decode([JSONValue].self)) }
    }
    func encode(to encoder: any Encoder) throws {
        var single = encoder.singleValueContainer()
        switch self { case let .object(value): try single.encode(value); case let .array(value): try single.encode(value); case let .string(value): try single.encode(value); case let .number(value): try single.encode(value); case let .bool(value): try single.encode(value); case .null: try single.encodeNil() }
    }
}
