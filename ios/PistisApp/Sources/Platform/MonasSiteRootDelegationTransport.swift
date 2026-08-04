import Foundation

/// The only currently documented Monas Site Root endpoints.
///
/// The readiness endpoint is present to report a deliberately unavailable
/// authority.  The submission endpoint is reserved by the v1 contract and is
/// not enabled until Monas has durable session, replay, and App Attest
/// adapters.  This client never substitutes another origin or endpoint.
enum MonasSiteRootDelegationEndpointV1 {
    static let readinessPath = "/auth/pistis/v1/site-root-delegation/readiness"
    static let submitPath = "/auth/pistis/site-root-delegations/v1/submit"
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
struct MonasSiteRootDelegationTransport: MonasSiteRootDelegationSubmitting,
    MonasSiteRootDelegationReadinessChecking, Sendable
{
    private static let maximumResponseBytes = 1_024
    private static let maximumSubmissionBytes = 90_000

    private let authorityOrigin: URL
    private let session: URLSession

    init(
        authorityOrigin: URL,
        configuration: URLSessionConfiguration = .ephemeral
    ) throws {
        guard Self.isValidOrigin(authorityOrigin) else {
            throw PlatformFailure.invalidConfiguration
        }
        self.authorityOrigin = authorityOrigin
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        self.session = URLSession(
            configuration: configuration,
            delegate: RedirectRejectingSessionDelegate(),
            delegateQueue: nil
        )
    }

    func readiness() async throws -> MonasSiteRootDelegationReadinessV1 {
        let endpoint = try endpoint(path: MonasSiteRootDelegationEndpointV1.readinessPath)
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 15
        let (data, response) = try await requestData(request, expectedURL: endpoint)
        do {
            return try JSONDecoder().decode(MonasReadinessResponse.self, from: data).value
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
    }

    func submit(_ request: MonasSiteRootDelegationSubmissionRequestV1) async throws
        -> MonasSiteRootDelegationSubmissionReceiptV1
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
        urlRequest.timeoutInterval = 15
        let (data, response) = try await requestData(urlRequest, expectedURL: request.endpoint)
        do {
            let receipt = try JSONDecoder().decode(MonasSubmissionReceipt.self, from: data)
            guard receipt.reference == request.submission.reference else {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
            return .init(reference: receipt.reference, accepted: receipt.state == .completed)
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

    private func requestData(_ request: URLRequest, expectedURL: URL) async throws
        -> (Data, URLResponse)
    {
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse,
                  (200 ... 299).contains(http.statusCode),
                  http.url == expectedURL,
                  data.count <= Self.maximumResponseBytes
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
            return (data, response)
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
    }

    private static func isValidOrigin(_ value: URL) -> Bool {
        value.scheme == "https" && value.host != nil && value.user == nil
            && value.password == nil && value.query == nil && value.fragment == nil
            && (value.path.isEmpty || value.path == "/")
    }

    private static func matchesAuthority(_ value: URL, origin: URL, expectedPath: String) -> Bool {
        value.scheme == "https" && value.host == origin.host && value.port == origin.port
            && value.user == nil && value.password == nil && value.query == nil
            && value.fragment == nil && value.path == expectedPath
    }
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

private struct MonasSubmissionReceipt: Decodable {
    enum State: String, Decodable { case completed, denied, expired, cancelled }
    let schema: String
    let reference: String
    let state: State

    private enum CodingKeys: String, CodingKey, CaseIterable { case schema, reference, state }
    init(from decoder: any Decoder) throws {
        let untyped = try decoder.container(keyedBy: MonasSiteRootWireKey.self)
        guard Set(untyped.allKeys.map(\.stringValue)) == Set(CodingKeys.allCases.map(\.rawValue)) else { throw DecodingError.dataCorruptedError(forKey: .schema, in: try decoder.container(keyedBy: CodingKeys.self), debugDescription: "unexpected receipt fields") }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        schema = try values.decode(String.self, forKey: .schema)
        reference = try values.decode(String.self, forKey: .reference)
        state = try values.decode(State.self, forKey: .state)
        guard schema == "monas.site-root-delegation-submission-receipt.v1", !reference.isEmpty, reference.utf8.count <= 128 else { throw DecodingError.dataCorruptedError(forKey: .schema, in: values, debugDescription: "invalid receipt") }
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
