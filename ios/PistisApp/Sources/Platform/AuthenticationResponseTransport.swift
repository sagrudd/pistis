import Foundation

enum AuthoritativeCeremonyState: String, Codable, Equatable, Sendable {
    case pending
    case accepted
    case denied
    case rejected
    case expired
    case cancelled

    var isTerminal: Bool { self != .pending }
}

struct AuthoritativeCeremonyStatus: Codable, Equatable, Sendable {
    let state: AuthoritativeCeremonyState
    let evidenceID: String?
}

/// Bounded HTTPS response delivery. A signed endpoint hint is transport input,
/// not authority; the caller supplies the host allow-list from enrolled trust.
struct AuthenticationResponseTransport: Sendable {
    private let allowedHosts: Set<String>
    private let session: URLSession
    private let maximumResponseBytes = 65_536

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
        guard !envelope.isEmpty, envelope.count <= 65_536 else {
            throw PlatformFailure.invalidConfiguration
        }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = envelope
        request.setValue("application/cose", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 15
        let (data, response) = try await session.data(for: request)
        return try decode(data: data, response: response)
    }

    func status(at endpoint: URL) async throws -> AuthoritativeCeremonyStatus {
        try validate(endpoint)
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 15
        let (data, response) = try await session.data(for: request)
        return try decode(data: data, response: response)
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

    private func decode(data: Data, response: URLResponse) throws
        -> AuthoritativeCeremonyStatus
    {
        guard let http = response as? HTTPURLResponse,
              (200 ... 299).contains(http.statusCode),
              data.count <= maximumResponseBytes
        else { throw PlatformFailure.productionEnvelopeUnavailable }
        do {
            return try JSONDecoder().decode(AuthoritativeCeremonyStatus.self, from: data)
        } catch {
            throw PlatformFailure.productionEnvelopeUnavailable
        }
    }
}
