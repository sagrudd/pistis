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
              !value.hasSuffix("."),
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
    private let session: URLSession

    init(
        allowedHosts: Set<String>,
        configuration: URLSessionConfiguration = .ephemeral
    ) throws {
        let canonicalHosts = Set(allowedHosts.compactMap(CanonicalHTTPSHost.parse))
        guard !allowedHosts.isEmpty, canonicalHosts.count == allowedHosts.count
        else { throw PlatformFailure.invalidConfiguration }
        self.allowedHosts = canonicalHosts
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(
            configuration: configuration,
            delegate: RedirectRejectingSessionDelegate(),
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
        let (data, response) = try await session.data(for: request)
        return try decode(data: data, response: response, expectedURL: endpoint)
    }

    func status(at endpoint: URL) async throws -> AuthoritativeCeremonyStatus {
        try validate(endpoint)
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 15
        let (data, response) = try await session.data(for: request)
        return try decode(data: data, response: response, expectedURL: endpoint)
    }

    private func validate(_ endpoint: URL) throws {
        guard endpoint.scheme == "https",
              endpoint.user == nil,
              endpoint.password == nil,
              endpoint.fragment == nil,
              let host = CanonicalHTTPSHost.from(endpoint),
              allowedHosts.contains(host)
        else { throw PlatformFailure.invalidConfiguration }
    }

    private func decode(data: Data, response: URLResponse, expectedURL: URL) throws
        -> AuthoritativeCeremonyStatus
    {
        guard let http = response as? HTTPURLResponse,
              (200 ... 299).contains(http.statusCode),
              http.url == expectedURL,
              data.count <= Self.maximumResponseBytes
        else { throw PlatformFailure.productionEnvelopeUnavailable }
        do {
            let status = try JSONDecoder().decode(AuthoritativeCeremonyStatus.self, from: data)
            guard status.evidenceID.map({
                    !$0.isEmpty && $0.utf8.count <= 128
                        && !$0.unicodeScalars.contains(
                            where: CharacterSet.controlCharacters.contains
                        )
                }) ?? true
            else { throw PlatformFailure.productionEnvelopeUnavailable }
            return status
        } catch {
            throw PlatformFailure.productionEnvelopeUnavailable
        }
    }
}
