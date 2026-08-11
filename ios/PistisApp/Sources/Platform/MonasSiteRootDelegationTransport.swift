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
/// The configured origin is enrolment/trust input, never QR input.  The QR
/// submission URL must exactly match that origin and the reviewed v1 path.
/// Redirects, cookies, caches, unexpected JSON and all non-success statuses
/// deny without retrying another endpoint.
struct MonasSiteRootDelegationTransport: MonasSiteRootCeremonyTransport,
    MonasSiteRootDelegationReadinessChecking, Sendable
{
    private static let maximumResponseBytes = 1_024
    private static let maximumSubmissionBytes = 90_000

    private let authorityOrigin: URL
    private let trustPolicy: MonasServerTrustPolicy
    private let session: URLSession

    var genesisAuthorityOrigin: URL? { authorityOrigin }
    var authorityHost: String? { authorityOrigin.host }

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
            authorityOrigin: authorityOrigin,
            trustPolicy: .bootstrapLeafSPKI(expectedSPKISHA256),
            configuration: configuration
        )
    }

    init(
        authorityOrigin: URL,
        trustPolicy: MonasServerTrustPolicy,
        configuration: URLSessionConfiguration = .ephemeral
    ) throws {
        guard Self.isValidOrigin(authorityOrigin) else {
            throw PlatformFailure.invalidConfiguration
        }
        self.authorityOrigin = authorityOrigin
        self.trustPolicy = trustPolicy
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        self.session = URLSession(
            configuration: configuration,
            delegate: try PinnedEnrolmentSessionDelegate(
                origin: authorityOrigin,
                trustPolicy: trustPolicy
            ),
            delegateQueue: nil
        )
    }

    func appAttestTransport() throws -> MonasAppAttestTransport {
        try MonasAppAttestTransport(
            authorityOrigin: authorityOrigin,
            trustPolicy: trustPolicy
        )
    }

    func siteRootConvergenceTransport() throws -> MonasSiteRootConvergenceTransport {
        try MonasSiteRootConvergenceTransport(
            authorityOrigin: authorityOrigin,
            trustPolicy: trustPolicy
        )
    }

    func readiness() async throws -> MonasSiteRootDelegationReadinessV1 {
        let endpoint = try endpoint(path: MonasSiteRootDelegationEndpointV1.readinessPath)
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.timeoutInterval = 15
        let (data, _) = try await requestData(request, expectedURL: endpoint)
        do {
            return try JSONDecoder().decode(MonasReadinessResponse.self, from: data).value
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
    }

    func authorityCustodyStatusV2() async throws -> AuthorityCustodyStatusV2 {
        let endpoint = try endpoint(
            path: "/v1/pistis/site-trust/authority-custody/v2/status"
        )
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.timeoutInterval = 15
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        guard let http = response as? HTTPURLResponse,
              http.url == endpoint,
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
        guard data.count <= 1_024,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
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
    }

    /// Reads only a matching, already proof-consumed Site Root lifecycle
    /// record. This is display reconciliation, never session or authority.
    func installationStatus(
        siteRootDeviceKeyID: String
    ) async throws -> MonasSiteRootInstallationStatusV1? {
        guard !siteRootDeviceKeyID.isEmpty,
              siteRootDeviceKeyID.utf8.count <= 128,
              siteRootDeviceKeyID.utf8.allSatisfy({
                  ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                      || ($0 >= 97 && $0 <= 122) || [45, 46, 58, 95].contains($0)
              })
        else { throw PlatformFailure.invalidConfiguration }
        let endpoint = try endpoint(path: MonasSiteRootDelegationEndpointV1.installationStatusPath)
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue(siteRootDeviceKeyID, forHTTPHeaderField: "X-Pistis-Site-Root-Key-ID")
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.url == endpoint else {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
            if http.statusCode == 404, data.isEmpty { return nil }
            guard http.statusCode == 200, data.count <= Self.maximumResponseBytes else {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
            return try MonasInstallationStatusResponse(data: data).value
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
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
            origin: authorityOrigin,
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
        var urlRequest = URLRequest(url: request.endpoint)
        urlRequest.httpMethod = "POST"
        urlRequest.httpBody = body
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        urlRequest.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        urlRequest.timeoutInterval = 15
        guard let nowUnixMillis = Self.nowUnixMillis() else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        let (data, _) = try await requestData(
            urlRequest,
            expectedURL: request.endpoint,
            expectedStatus: 200
        )
        do {
            return try MonasAppAttestBootstrapResponse(
                data: data,
                authorityOrigin: authorityOrigin,
                nowUnixMillis: nowUnixMillis
            ).bootstrap
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
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
            origin: authorityOrigin,
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
        var urlRequest = URLRequest(url: request.endpoint)
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
                  http.url == request.endpoint,
                  data.isEmpty,
                  http.value(forHTTPHeaderField: "Set-Cookie") == nil
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
    }

    /// Posts the sole public first-device registration to the fixed, pinned
    /// authority. The response may contain only the issued one-time canonical
    /// delegation and its binding facts; it cannot select a new endpoint.
    func registerGenesis(_ request: SiteRootGenesisRegistrationRequestV1) async throws
        -> SiteRootDelegationPresentationV1
    {
        guard Self.matchesAuthority(
            request.presentation.registrationURL,
            origin: authorityOrigin,
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
        var urlRequest = URLRequest(url: request.presentation.registrationURL)
        urlRequest.httpMethod = "POST"
        urlRequest.httpBody = body
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        urlRequest.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        urlRequest.timeoutInterval = 15
        let (data, _) = try await requestData(
            urlRequest,
            expectedURL: request.presentation.registrationURL,
            expectedStatus: 200,
            maximumResponseBytes: Self.maximumSubmissionBytes
        )
        do {
            return try MonasSiteRootGenesisRegistrationResult(
                data: data,
                request: request,
                authorityOrigin: authorityOrigin
            ).presentation
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
    }

    private func endpoint(path: String) throws -> URL {
        guard let endpoint = URL(string: path, relativeTo: authorityOrigin)?.absoluteURL,
              Self.matchesAuthority(endpoint, origin: authorityOrigin, expectedPath: path)
        else { throw PlatformFailure.invalidConfiguration }
        return endpoint
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
            throw failure
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
    }

    fileprivate static func isValidOrigin(_ value: URL) -> Bool {
        value.scheme == "https" && value.host != nil && value.user == nil
            && value.password == nil && value.query == nil && value.fragment == nil
            && value.path.isEmpty
    }

    static func matchesAuthority(_ value: URL, origin: URL, expectedPath: String) -> Bool {
        value.scheme == "https" && value.host == origin.host && value.port == origin.port
            && value.user == nil && value.password == nil && value.query == nil
            && value.fragment == nil && value.path == expectedPath
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
              origin.absoluteString == authorityOrigin.absoluteString,
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

private struct MonasSiteRootWireKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

private enum JSONValue: Codable {
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
