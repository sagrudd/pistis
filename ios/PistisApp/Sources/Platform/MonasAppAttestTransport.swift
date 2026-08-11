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

struct CustodyRotationAppAttestChallengeV2: Sendable {
    static let schema = "monas.first-authority-custody-app-attest-challenge.v2"
    let ceremonyID: Data
    let clientDataHash: Data
    let keyID: Data
    let expiresAtUnixSeconds: UInt64

    init(data: Data, nowUnixSeconds: UInt64) throws {
        let object = try StrictJSONObject(data: data, maximumBytes: 8_192)
        let keys: Set<String> = [
            "schema", "installation_id_b64url", "site_trust_domain",
            "ceremony_id_b64url", "client_data_hash_b64url", "app_identifier",
            "key_id_b64url", "issued_at_unix_seconds", "expires_at_unix_seconds",
        ]
        guard Set(object.values.keys) == keys else {
            throw PlatformFailure.productionEnvelopeUnavailable
        }
        let wire = try JSONDecoder().decode(Wire.self, from: data)
        guard wire.schema == Self.schema,
              wire.appIdentifier == AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
              !wire.siteTrustDomain.isEmpty, wire.siteTrustDomain.utf8.count <= 255,
              Self.decode(wire.installationIDB64URL, count: 16) != nil,
              let ceremony = Self.decode(wire.ceremonyIDB64URL, count: 16),
              let hash = Self.decode(wire.clientDataHashB64URL, count: 32),
              let key = Self.decode(wire.keyIDB64URL, count: 32),
              wire.issuedAtUnixSeconds <= nowUnixSeconds,
              nowUnixSeconds < wire.expiresAtUnixSeconds,
              wire.expiresAtUnixSeconds - wire.issuedAtUnixSeconds <= 900
        else { throw PlatformFailure.productionEnvelopeUnavailable }
        ceremonyID = ceremony
        clientDataHash = hash
        keyID = key
        expiresAtUnixSeconds = wire.expiresAtUnixSeconds
    }

    private struct Wire: Decodable {
        let schema: String
        let installationIDB64URL: String
        let siteTrustDomain: String
        let ceremonyIDB64URL: String
        let clientDataHashB64URL: String
        let appIdentifier: String
        let keyIDB64URL: String
        let issuedAtUnixSeconds: UInt64
        let expiresAtUnixSeconds: UInt64
        enum CodingKeys: String, CodingKey {
            case schema
            case installationIDB64URL = "installation_id_b64url"
            case siteTrustDomain = "site_trust_domain"
            case ceremonyIDB64URL = "ceremony_id_b64url"
            case clientDataHashB64URL = "client_data_hash_b64url"
            case appIdentifier = "app_identifier"
            case keyIDB64URL = "key_id_b64url"
            case issuedAtUnixSeconds = "issued_at_unix_seconds"
            case expiresAtUnixSeconds = "expires_at_unix_seconds"
        }
    }

    private static func decode(_ value: String, count: Int) -> Data? {
        guard !value.contains("="), value.utf8.allSatisfy({ byte in
            (48...57).contains(byte) || (65...90).contains(byte)
                || (97...122).contains(byte) || byte == 45 || byte == 95
        }) else { return nil }
        let standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let data = Data(base64Encoded: standard), data.count == count,
              !data.allSatisfy({ $0 == 0 }) else { return nil }
        return data
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
    private static let mtgsRecoveryAssertionPath =
        "/v1/pistis/site-trust/mtgs-recovery/v1/assertion"
    private static let custodyRewrapSubmissionPath =
        "/v1/pistis/site-trust/custody-rewrap/submit"
    private static let authorityCustodyRotationBeginPath =
        "/v1/pistis/site-trust/authority-custody-rotation/v2/begin"
    private static let authorityCustodyRotationChallengePath =
        "/v1/pistis/site-trust/authority-custody-rotation/v2/assertion-challenge"
    private static let authorityCustodyRotationCompletePath =
        "/v1/pistis/site-trust/authority-custody-rotation/v2/complete"
    private static let authorityCustodyRecoveryBeginPath =
        "/v1/pistis/site-trust/authority-custody-recovery/v2/begin"
    private static let authorityCustodyRecoveryCompletePath =
        "/v1/pistis/site-trust/authority-custody-recovery/v2/complete"
    private let origin: URL
    private let session: URLSession

    init(
        bootstrap: MonasAppAttestCeremonyBootstrap,
        configuration: URLSessionConfiguration = .ephemeral
    ) throws {
        try self.init(
            authorityOrigin: bootstrap.httpsOrigin,
            expectedSPKISHA256: bootstrap.tlsSPKISHA256,
            configuration: configuration
        )
    }

    init(
        authorityOrigin: URL,
        expectedSPKISHA256: Data,
        configuration: URLSessionConfiguration = .ephemeral
    ) throws {
        guard expectedSPKISHA256.count == 32,
              !expectedSPKISHA256.allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.appAttestInvalidInput }
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
        guard authorityOrigin.scheme == "https", authorityOrigin.host != nil
        else { throw PlatformFailure.appAttestInvalidInput }
        origin = authorityOrigin
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(
            configuration: configuration,
            delegate: try PinnedEnrolmentSessionDelegate(
                origin: authorityOrigin,
                trustPolicy: trustPolicy
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

    /// Submits one recovery assertion to the fixed, purpose-separated Monas route.
    /// The QR cannot override this path and no retry or fallback is attempted.
    func submitMTGSRecoveryAssertion(
        _ envelope: AppleAppAttestAssertionEnvelope
    ) async throws {
        try await submit(
            envelope,
            path: Self.mtgsRecoveryAssertionPath,
            maximumRequestBytes: 32_768
        )
    }

    func fetchCustodyRotationAssertionChallengeV2(
        nowUnixSeconds: UInt64
    ) async throws -> CustodyRotationAppAttestChallengeV2 {
        guard let endpoint = URL(
            string: Self.authorityCustodyRotationChallengePath, relativeTo: origin
        )?.absoluteURL,
        endpoint.absoluteString == origin.absoluteString + Self.authorityCustodyRotationChallengePath
        else { throw PlatformFailure.productionEnvelopeUnavailable }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.url == endpoint,
              http.statusCode == 200,
              http.value(forHTTPHeaderField: "Cache-Control")?
                .lowercased().contains("no-store") == true
        else { throw PlatformFailure.productionEnvelopeUnavailable }
        return try CustodyRotationAppAttestChallengeV2(
            data: data, nowUnixSeconds: nowUnixSeconds
        )
    }

    /// Delivers an App Attest assertion through the one pinned Monas ingress
    /// and accepts a custody presentation only as its terminal retained-session
    /// response. The same fixed URL is used; this method does not discover or
    /// select a second endpoint, cookie, token, browser state, or fallback.
    ///
    /// A normal assertion remains 202/empty. This stricter operation accepts
    /// only a 200 no-store response matching the custody relay schema, which a
    /// future Monas runtime may issue only after it has retained the session
    /// and contacted its fixed Thesaurophylax peer.
    func submitAssertionForCustodyPresentation(
        _ envelope: AppleAppAttestAssertionEnvelope,
        nowUnixSeconds: UInt64
    ) async throws -> IphoneMediatedCustodyRewrapPresentationV1 {
        let body = try JSONEncoder.sorted.encode(envelope)
        guard !body.isEmpty,
              body.count <= 32_768,
              let endpoint = URL(string: Self.assertionPath, relativeTo: origin)?.absoluteURL,
              endpoint.absoluteString == origin.absoluteString + Self.assertionPath
        else { throw PlatformFailure.custodyRewrapUnavailable }
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
                  http.statusCode == 200,
                  !data.isEmpty,
                  data.count <= 16_384,
                  http.value(forHTTPHeaderField: "Cache-Control")?
                      .lowercased().contains("no-store") == true
            else { throw PlatformFailure.custodyRewrapUnavailable }
            return try MonasRetainedCustodyPresentationResponseV1(
                data: data, nowUnixSeconds: nowUnixSeconds
            ).presentation
        } catch let error as PlatformFailure {
            throw error
        } catch {
            throw PlatformFailure.custodyRewrapUnavailable
        }
    }

    /// Sends exactly one transient Secure Enclave rewrap response to Monas's
    /// fixed custody submission endpoint. This carries no cookie, bearer,
    /// browser state, local identity, endpoint override, retry or fallback.
    /// Monas must bind its correlation to the retained App Attest session and
    /// pass the opaque result only to its fixed Thesaurophylax peer.
    func submitCustodyRewrap(_ submission: IphoneMediatedCustodyRewrapSubmissionV1) async throws {
        try await submit(
            MonasRetainedCustodyRewrapSubmissionV1(submission),
            path: Self.custodyRewrapSubmissionPath,
            maximumRequestBytes: 16_384
        )
    }

    /// Fetches one role-fixed THESXIR2 presentation from the protected Monas
    /// origin. The request is bodyless and carries no cookie, bearer, browser
    /// state, endpoint hint or retry/fallback authority.
    func fetchSiteX509AttendedUnlockV2(
        role: SiteX509AttendedUnlockRoleV2,
        nowUnixSeconds: UInt64
    ) async throws -> SiteX509AttendedUnlockPresentationV2 {
        let (data, response, _) = try await siteX509Request(
            body: nil, method: "GET", path: role.presentationPath
        )
        guard response.statusCode == 200, !data.isEmpty,
              response.value(forHTTPHeaderField: "Cache-Control")?
                .lowercased().contains("no-store") == true
        else { throw PlatformFailure.custodyRewrapUnavailable }
        return try SiteX509AttendedUnlockPresentationV2(
            data: data, expectedRole: role, nowUnixSeconds: nowUnixSeconds
        )
    }

    /// Submits one exact role-bound P-256 scalar rewrap and accepts only the
    /// corresponding role/purpose acknowledgement from the same fixed route.
    func submitSiteX509AttendedUnlockV2(
        _ submission: SiteX509AttendedUnlockSubmissionV2,
        role: SiteX509AttendedUnlockRoleV2
    ) async throws {
        guard submission.role == role.rawValue, submission.purpose == role.purpose else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let body = try JSONEncoder.sorted.encode(submission)
        let (data, response, _) = try await siteX509Request(
            body: body, method: "POST", path: role.submissionPath
        )
        guard response.statusCode == 200, !data.isEmpty,
              response.value(forHTTPHeaderField: "Cache-Control")?
                .lowercased().contains("no-store") == true
        else { throw PlatformFailure.custodyRewrapUnavailable }
        let accepted = try SiteX509AttendedUnlockAcceptedV2(data: data)
        guard accepted.role == role.rawValue, accepted.purpose == role.purpose else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
    }

    func beginSiteX509LeafApprovalV1(
        delegationSerial: String,
        delegationExpiresAt: UInt64,
        nowUnixSeconds: UInt64
    ) async throws -> SiteX509LeafApprovalPresentationV1 {
        let body = try JSONEncoder.sorted.encode(SiteX509LeafApprovalBeginV1(
            delegationSerial: delegationSerial,
            delegationExpiresAt: delegationExpiresAt
        ))
        let (data, response, _) = try await siteX509Request(
            body: body, method: "POST", path: SiteX509LeafApprovalProfileV1.presentationPath
        )
        guard response.statusCode == 200, !data.isEmpty,
              response.value(forHTTPHeaderField: "Cache-Control")?
                .lowercased().contains("no-store") == true
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        let presentation = try SiteX509LeafApprovalPresentationV1(
            data: data, nowUnixSeconds: nowUnixSeconds
        )
        guard presentation.delegationSerial == delegationSerial,
              presentation.delegationExpiresAt == delegationExpiresAt else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        return presentation
    }

    func submitSiteX509LeafApprovalV1(
        _ submission: SiteX509LeafApprovalSubmissionV1,
        presentation: SiteX509LeafApprovalPresentationV1
    ) async throws {
        let body = try JSONEncoder.sorted.encode(submission)
        let (data, response, _) = try await siteX509Request(
            body: body, method: "POST", path: SiteX509LeafApprovalProfileV1.submitPath
        )
        guard response.statusCode == 200, !data.isEmpty,
              response.value(forHTTPHeaderField: "Cache-Control")?
                .lowercased().contains("no-store") == true
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        _ = try SiteX509LeafApprovalAcceptedV1(data: data, expected: presentation)
    }

    private func siteX509Request(
        body: Data?, method: String, path: String
    ) async throws -> (Data, HTTPURLResponse, URL) {
        guard (method == "GET" && body == nil) || (method == "POST" && body != nil),
              body?.count ?? 0 <= 16_384,
              let endpoint = URL(string: path, relativeTo: origin)?.absoluteURL,
              endpoint.absoluteString == origin.absoluteString + path
        else { throw PlatformFailure.custodyRewrapUnavailable }
        var request = URLRequest(url: endpoint)
        request.httpMethod = method
        request.httpBody = body
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        if body != nil {
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        }
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.url == endpoint,
                  data.count <= 16_384
            else { throw PlatformFailure.custodyRewrapUnavailable }
            return (data, http, endpoint)
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.custodyRewrapUnavailable
        }
    }

    /// Begins the distinct v2 first-authority rotation only through the
    /// already verified, SPKI-pinned App Attest session. No caller supplies a
    /// URL, retained binding, credential, or alternate transport.
    func beginFirstAuthorityCustodyRotationV2(
        _ commitment: FirstAuthorityCustodySeedCommitmentV2,
        nowUnixSeconds: UInt64
    ) async throws -> FirstAuthorityRotationPresentationV2 {
        let body = try JSONEncoder.sorted.encode(
            FirstAuthorityCustodyRotationV2Wire.Begin(commitment)
        )
        let (data, response, endpoint) = try await authorityCustodyRequest(
            body: body, path: Self.authorityCustodyRotationBeginPath
        )
        guard response.statusCode == 200, !data.isEmpty,
              response.value(forHTTPHeaderField: "Cache-Control")?
                  .lowercased().contains("no-store") == true
        else { throw PlatformFailure.custodyRewrapUnavailable }
        _ = endpoint
        return try FirstAuthorityCustodyRotationV2Wire.presentation(
            data: data, expectedCommitment: commitment, nowUnixSeconds: nowUnixSeconds
        )
    }

    /// Completes exactly one retained v2 correlation and accepts success only
    /// when Monas returns the matching typed authority descriptor.
    func completeFirstAuthorityCustodyRotationV2(
        _ submission: FirstAuthorityCustodySubmissionV2
    ) async throws -> FirstAuthorityCustodyAcceptedV2 {
        let body = try JSONEncoder.sorted.encode(
            FirstAuthorityCustodyRotationV2Wire.Complete(submission)
        )
        let (data, response, endpoint) = try await authorityCustodyRequest(
            body: body, path: Self.authorityCustodyRotationCompletePath
        )
        guard response.statusCode == 200, !data.isEmpty,
              response.value(forHTTPHeaderField: "Cache-Control")?
                  .lowercased().contains("no-store") == true
        else { throw PlatformFailure.custodyRewrapUnavailable }
        _ = endpoint
        return try FirstAuthorityCustodyRotationV2Wire.accepted(
            data: data, expectedCorrelation: submission.correlation
        )
    }

    func beginFirstAuthorityCustodyRecoveryV2(
        expectedCommitment: FirstAuthorityCustodySeedCommitmentV2,
        nowUnixSeconds: UInt64
    ) async throws -> FirstAuthorityRecoveryPresentationV2 {
        let body = try JSONEncoder.sorted.encode(
            FirstAuthorityCustodyRotationV2Wire.RecoveryBegin()
        )
        let (data, response, _) = try await authorityCustodyRequest(
            body: body, path: Self.authorityCustodyRecoveryBeginPath
        )
        guard response.statusCode == 200, !data.isEmpty,
              response.value(forHTTPHeaderField: "Cache-Control")?
                  .lowercased().contains("no-store") == true
        else { throw PlatformFailure.custodyRewrapUnavailable }
        return try FirstAuthorityCustodyRotationV2Wire.recoveryPresentation(
            data: data, expectedDeviceKeyID: expectedCommitment.deviceKeyID,
            expectedEnrolledPublicKey: expectedCommitment.enrolledDevicePublicSEC1,
            expectedRecoveryCommitment: expectedCommitment.recoverySeedEd25519PublicKey,
            nowUnixSeconds: nowUnixSeconds
        )
    }

    func completeFirstAuthorityCustodyRecoveryV2(
        _ submission: FirstAuthorityCustodySubmissionV2
    ) async throws -> FirstAuthorityCustodyAcceptedV2 {
        let body = try JSONEncoder.sorted.encode(
            FirstAuthorityCustodyRotationV2Wire.RecoveryComplete(submission)
        )
        let (data, response, _) = try await authorityCustodyRequest(
            body: body, path: Self.authorityCustodyRecoveryCompletePath
        )
        guard response.statusCode == 200, !data.isEmpty,
              response.value(forHTTPHeaderField: "Cache-Control")?
                  .lowercased().contains("no-store") == true
        else { throw PlatformFailure.custodyRewrapUnavailable }
        return try FirstAuthorityCustodyRotationV2Wire.accepted(
            data: data, expectedCorrelation: submission.correlation,
            schema: FirstAuthorityCustodyRotationV2Wire.recoveryAcceptedSchema
        )
    }

    private func authorityCustodyRequest(
        body: Data, path: String
    ) async throws -> (Data, HTTPURLResponse, URL) {
        guard !body.isEmpty, body.count <= 32_768,
              let endpoint = URL(string: path, relativeTo: origin)?.absoluteURL,
              endpoint.absoluteString == origin.absoluteString + path
        else { throw PlatformFailure.custodyRewrapUnavailable }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.httpBody = body
        request.timeoutInterval = 15
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.url == endpoint,
                  data.count <= 32_768
            else { throw PlatformFailure.custodyRewrapUnavailable }
            return (data, http, endpoint)
        } catch let failure as PlatformFailure {
            throw failure
        } catch {
            throw PlatformFailure.custodyRewrapUnavailable
        }
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
