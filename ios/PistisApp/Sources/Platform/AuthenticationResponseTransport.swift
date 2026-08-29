import Foundation

enum AuthoritativeCeremonyState: String, Codable, Equatable, Sendable {
    case pending
    case completed
    case denied
    case rejected
    case expired
    case cancelled

    var isTerminal: Bool { self != .pending }
}

struct AuthoritativeCeremonyStatus: Codable, Equatable, Sendable {
    let state: AuthoritativeCeremonyState
    let evidenceID: String?

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case state
        case evidenceID = "evidence_id"
    }

    init(state: AuthoritativeCeremonyState, evidenceID: String?) {
        self.state = state
        self.evidenceID = evidenceID
    }

    init(from decoder: any Decoder) throws {
        let untyped = try decoder.container(keyedBy: WireCodingKey.self)
        let allowed = Set(CodingKeys.allCases.map(\.rawValue))
        guard Set(untyped.allKeys.map(\.stringValue)).isSubset(of: allowed) else {
            throw DecodingError.dataCorrupted(
                .init(codingPath: decoder.codingPath, debugDescription: "unknown status field")
            )
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decode(AuthoritativeCeremonyState.self, forKey: .state)
        evidenceID = try container.decodeIfPresent(String.self, forKey: .evidenceID)
    }
}

private struct WireCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    init?(intValue: Int) {
        stringValue = String(intValue)
        self.intValue = intValue
    }
}

enum CanonicalHTTPSHost {
    static func parse(_ value: String) -> String? {
        guard value == value.lowercased(),
              value.utf8.count <= 253,
              value.unicodeScalars.allSatisfy(\.isASCII),
              !value.hasSuffix(".")
        else { return nil }
        if isCanonicalIPv4Address(value) { return value }
        guard !isNumericIPAddressForm(value),
              value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({
                  !$0.isEmpty && $0.utf8.count <= 63
                      && $0.first != "-" && $0.last != "-"
                      && $0.utf8.allSatisfy {
                          (48 ... 57).contains($0)
                              || (97 ... 122).contains($0) || $0 == 45
                      }
              })
        else { return nil }
        return value
    }

    /// Local Monas appliances may be enrolled before site DNS exists. The
    /// signed presentation and TLS SPKI pin still bind the endpoint; accepting
    /// only the unique dotted-decimal spelling prevents address ambiguity.
    private static func isCanonicalIPv4Address(_ host: String) -> Bool {
        let components = host.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 4 else { return false }
        return components.allSatisfy { component in
            let bytes = Array(component.utf8)
            guard !bytes.isEmpty, bytes.count <= 3,
                  bytes.allSatisfy({ (48 ... 57).contains($0) }),
                  bytes.count == 1 || bytes[0] != 48,
                  let octet = UInt16(component), octet <= 255
            else { return false }
            return true
        }
    }

    static func from(_ endpoint: URL) -> String? {
        guard let components = URLComponents(
            url: endpoint,
            resolvingAgainstBaseURL: false
        ),
            components.scheme == "https",
            let host = components.host,
            components.percentEncodedHost == host
        else { return nil }
        return parse(host)
    }

    private static func isNumericIPAddressForm(_ host: String) -> Bool {
        let components = host.split(separator: ".", omittingEmptySubsequences: false)
        guard (1 ... 4).contains(components.count) else { return false }
        return components.allSatisfy(isNumericAddressComponent)
    }

    private static func isNumericAddressComponent(_ component: Substring) -> Bool {
        let bytes = Array(component.utf8)
        guard !bytes.isEmpty else { return false }
        if bytes.count > 2, bytes[0] == 48, bytes[1] == 120 {
            return bytes.dropFirst(2).allSatisfy {
                (48 ... 57).contains($0) || (97 ... 102).contains($0)
            }
        }
        if bytes.count > 1, bytes[0] == 48 {
            return bytes.dropFirst().allSatisfy { (48 ... 55).contains($0) }
        }
        return bytes.allSatisfy { (48 ... 57).contains($0) }
    }
}

/// Canonical HTTPS origin from the signed first-device presentation.
///
/// An origin is stored as its exact canonical spelling, including an explicit
/// non-default port when present. This prevents later authentication from
/// silently changing the authority while retaining the same hostname.
enum CanonicalHTTPSOrigin {
    static func parse(_ value: String) -> String? {
        guard value == value.lowercased(),
              value.utf8.count <= 255,
              value.unicodeScalars.allSatisfy(\.isASCII),
              !value.contains("%"),
              let url = URL(string: value),
              let components = URLComponents(
                  url: url,
                  resolvingAgainstBaseURL: false
              ),
              components.scheme == "https",
              components.user == nil,
              components.password == nil,
              components.path.isEmpty,
              components.query == nil,
              components.fragment == nil,
              let host = components.host,
              components.percentEncodedHost == host,
              components.port != 443,
              components.string == value,
              CanonicalHTTPSHost.parse(host) != nil
        else { return nil }
        return value
    }

    static func from(_ endpoint: URL) -> String? {
        guard let components = URLComponents(
            url: endpoint,
            resolvingAgainstBaseURL: false
        ),
            components.scheme == "https",
            components.user == nil,
            components.password == nil,
            components.fragment == nil,
            let host = components.host,
            components.percentEncodedHost == host,
            CanonicalHTTPSHost.parse(host) != nil
        else { return nil }
        var origin = components
        origin.path = ""
        origin.query = nil
        origin.fragment = nil
        guard let value = origin.string else { return nil }
        return parse(value)
    }
}

/// Redirects are refused at the URL loading boundary. Validating only the final
/// response URL would be too late because URLSession may already have replayed
/// a signed POST body to the redirect target.
final class RedirectRejectingSessionDelegate:
    NSObject, URLSessionTaskDelegate, @unchecked Sendable
{
    func urlSession(
        _: URLSession,
        task _: URLSessionTask,
        willPerformHTTPRedirection _: HTTPURLResponse,
        newRequest _: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

/// Bounded HTTPS response delivery. A signed endpoint hint is transport input,
/// not authority; the caller supplies the host allow-list from enrolled trust.
struct AuthenticationResponseTransport: Sendable {
    static let maximumEnvelopeBytes = 2_048
    static let maximumResponseBytes = 2_048

    private let allowedHosts: Set<String>
    private let httpsOrigin: String
    private let session: URLSession

    init(
        allowedHosts: Set<String>,
        httpsOrigin: String,
        tlsSPKISHA256: Data,
        configuration: URLSessionConfiguration = .ephemeral
    ) throws {
        let canonicalHosts = Set(allowedHosts.compactMap(CanonicalHTTPSHost.parse))
        guard !allowedHosts.isEmpty,
              canonicalHosts.count == allowedHosts.count,
              let canonicalOrigin = CanonicalHTTPSOrigin.parse(httpsOrigin),
              let originURL = URL(string: canonicalOrigin),
              let originHost = CanonicalHTTPSHost.from(originURL),
              canonicalHosts.contains(originHost),
              tlsSPKISHA256.count == 32,
              !tlsSPKISHA256.allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.invalidConfiguration }
        self.allowedHosts = canonicalHosts
        self.httpsOrigin = canonicalOrigin
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(
            configuration: configuration,
            delegate: try PinnedEnrolmentSessionDelegate(
                origin: originURL,
                expectedSPKISHA256: tlsSPKISHA256
            ),
            delegateQueue: nil
        )
    }

    func submit(envelope: Data, to endpoint: URL) async throws
        -> AuthoritativeCeremonyStatus
    {
        try validate(endpoint)
        guard !envelope.isEmpty, envelope.count <= Self.maximumEnvelopeBytes else {
            throw PlatformFailure.invalidConfiguration
        }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = envelope
        request.setValue("application/cose", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 15
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw PlatformFailure.authenticationTransportUnavailable
        }
        return try decode(data: data, response: response, expectedURL: endpoint)
    }

    func status(at endpoint: URL) async throws -> AuthoritativeCeremonyStatus {
        try validate(endpoint)
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 15
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw PlatformFailure.authenticationTransportUnavailable
        }
        return try decode(data: data, response: response, expectedURL: endpoint)
    }

    private func validate(_ endpoint: URL) throws {
        guard endpoint.scheme == "https",
              endpoint.user == nil,
              endpoint.password == nil,
              endpoint.fragment == nil,
              let host = CanonicalHTTPSHost.from(endpoint),
              allowedHosts.contains(host),
              CanonicalHTTPSOrigin.from(endpoint) == httpsOrigin
        else { throw PlatformFailure.invalidConfiguration }
    }

    private func decode(data: Data, response: URLResponse, expectedURL: URL) throws
        -> AuthoritativeCeremonyStatus
    {
        guard let http = response as? HTTPURLResponse,
              http.url == expectedURL,
              data.count <= Self.maximumResponseBytes
        else { throw PlatformFailure.authenticationAuthorityResponseInvalid }
        if http.statusCode == 401 || http.statusCode == 403 {
            throw PlatformFailure.authenticationResponseRejected
        }
        guard (200 ... 299).contains(http.statusCode) else {
            throw PlatformFailure.authenticationAuthorityResponseInvalid
        }
        do {
            let status = try JSONDecoder().decode(AuthoritativeCeremonyStatus.self, from: data)
            guard status.evidenceID.map({
                    !$0.isEmpty && $0.utf8.count <= 128
                        && !$0.unicodeScalars.contains(
                            where: CharacterSet.controlCharacters.contains
                        )
                }) ?? true
            else { throw PlatformFailure.authenticationAuthorityResponseInvalid }
            return status
        } catch {
            throw PlatformFailure.authenticationAuthorityResponseInvalid
        }
    }
}
