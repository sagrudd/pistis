import Foundation

/// Immutable values accepted only after the Monas ceremony bootstrap has been
/// verified by its pinned Site Trust path. This is deliberately not a QR or
/// browser input model.
struct MonasAppAttestCeremonyBootstrap: Sendable {
    let httpsOrigin: URL
    let tlsSPKISHA256: Data
    let ceremonyID: Data
    let challengeDigest: Data

    init(
        httpsOrigin: URL,
        tlsSPKISHA256: Data,
        ceremonyID: Data,
        challengeDigest: Data
    ) throws {
        guard httpsOrigin.scheme == "https",
              httpsOrigin.host != nil,
              httpsOrigin.user == nil,
              httpsOrigin.password == nil,
              httpsOrigin.path.isEmpty || httpsOrigin.path == "/",
              httpsOrigin.query == nil,
              httpsOrigin.fragment == nil,
              tlsSPKISHA256.count == 32,
              !tlsSPKISHA256.allSatisfy({ $0 == 0 }),
              ceremonyID.count == 16,
              !ceremonyID.allSatisfy({ $0 == 0 }),
              challengeDigest.count == 32,
              !challengeDigest.allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.appAttestInvalidInput }
        self.httpsOrigin = httpsOrigin
        self.tlsSPKISHA256 = tlsSPKISHA256
        self.ceremonyID = ceremonyID
        self.challengeDigest = challengeDigest
    }
}

/// Dedicated, pinned HTTPS JSON transport for App Attest. It cannot submit
/// generic COSE or consume cookies, redirects, cache entries, browser state,
/// endpoint hints, or local identity.
struct MonasAppAttestTransport: Sendable {
    private static let registrationPath =
        "/v1/pistis/site-trust/app-attest/registration"
    private static let assertionPath =
        "/v1/pistis/site-trust/app-attest/assertion"
    private let origin: URL
    private let session: URLSession

    init(
        bootstrap: MonasAppAttestCeremonyBootstrap,
        configuration: URLSessionConfiguration = .ephemeral
    ) throws {
        origin = bootstrap.httpsOrigin
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(
            configuration: configuration,
            delegate: try PinnedEnrolmentSessionDelegate(
                origin: bootstrap.httpsOrigin,
                expectedSPKISHA256: bootstrap.tlsSPKISHA256
            ),
            delegateQueue: nil
        )
    }

    func submitRegistration(_ envelope: AppleAppAttestRegistrationEnvelope) async throws {
        try await submit(
            envelope,
            path: Self.registrationPath,
            maximumRequestBytes: 196_608
        )
    }

    func submitAssertion(_ envelope: AppleAppAttestAssertionEnvelope) async throws {
        try await submit(
            envelope,
            path: Self.assertionPath,
            maximumRequestBytes: 32_768
        )
    }

    private func submit<T: Encodable>(
        _ envelope: T,
        path: String,
        maximumRequestBytes: Int
    ) async throws {
        let body = try JSONEncoder.sorted.encode(envelope)
        guard !body.isEmpty,
              body.count <= maximumRequestBytes,
              let endpoint = URL(string: path, relativeTo: origin)?.absoluteURL,
              endpoint.absoluteString == origin.absoluteString + path
        else { throw PlatformFailure.appAttestInvalidInput }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = body
        request.timeoutInterval = 15
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse,
                  http.url == endpoint,
                  http.statusCode == 202,
                  data.isEmpty,
                  http.value(forHTTPHeaderField: "Cache-Control")?
                      .lowercased().contains("no-store") == true
            else { throw PlatformFailure.productionEnvelopeUnavailable }
        } catch let error as PlatformFailure {
            throw error
        } catch {
            throw PlatformFailure.productionEnvelopeUnavailable
        }
    }
}

private extension JSONEncoder {
    static let sorted: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }()
}
