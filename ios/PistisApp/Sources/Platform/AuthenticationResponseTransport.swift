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

    private enum CodingKeys: String, CodingKey {
        case state
        case evidenceID = "evidence_id"
    }
}

/// Bounded HTTPS response delivery. A signed endpoint hint is transport input,
/// not authority; the caller supplies the host allow-list from enrolled trust.
struct AuthenticationResponseTransport: Sendable {
    static let maximumEnvelopeBytes = 2_048
    static let maximumResponseBytes = 2_048

    private let allowedHosts: Set<String>
    private let session: URLSession

    init(allowedHosts: Set<String>, session: URLSession = .shared) throws {
        guard !allowedHosts.isEmpty,
              allowedHosts.allSatisfy({
                  !$0.isEmpty && $0 == $0.lowercased() && !$0.contains("/")
              })
        else { throw PlatformFailure.invalidConfiguration }
        self.allowedHosts = allowedHosts
        self.session = session
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
              let host = endpoint.host?.lowercased(),
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
