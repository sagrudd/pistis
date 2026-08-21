import Foundation

/// One short-lived, server-issued invitation for the first Site Root device.
///
/// This is deliberately a distinct QR family from a completed Site Root
/// delegation. The QR can name neither an authority nor an arbitrary endpoint:
/// its registration URL must match the origin compiled into this Pistis build.
struct SiteRootGenesisRegistrationPresentationV1: Sendable {
    static let schema = "monas.site-root-genesis-registration-presentation.v1"
    static let maximumPayloadLength = 8_192
    static let maximumLifetimeMillis: UInt64 = 300_000

    let reference: String
    let correlation: Data?
    let siteTrustDomain: String
    let registrationURL: URL
    let appAttestCeremonyIDB64URL: String
    let appAttestChallengeDigest: Data
    let expiresAtUnixMillis: UInt64

    init(qrText: String, authorityOrigin: URL, nowUnixMillis: UInt64) throws {
        try self.init(
            qrText: qrText,
            authorityOrigins: [authorityOrigin],
            nowUnixMillis: nowUnixMillis
        )
    }

    init(
        qrText: String,
        authorityOrigins: [URL],
        nowUnixMillis: UInt64,
        requireCorrelation: Bool = false
    ) throws {
        guard qrText.utf8.count <= Self.maximumPayloadLength,
              let data = qrText.data(using: .utf8)
        else { throw PlatformFailure.qrPayloadUnsupported }

        let values: [String: StrictJSONObject.Value]
        do {
            values = try StrictJSONObject(data: data, maximumBytes: Self.maximumPayloadLength).values
        } catch {
            throw PlatformFailure.qrPayloadUnsupported
        }
        let required: Set<String> = [
            "schema", "reference", "site_trust_domain", "registration_url",
            "app_attest_ceremony_id_b64url", "app_attest_challenge_digest_b64url",
            "expires_at_unix_millis",
        ]
        let brokerRequired = required.union(["correlation_b64url"])
        guard Set(values.keys) == required || Set(values.keys) == brokerRequired,
              case let .string(schema)? = values["schema"], schema == Self.schema,
              case let .string(reference)? = values["reference"], Self.validIdentifier(reference),
              case let .string(siteTrustDomain)? = values["site_trust_domain"],
              Self.validIdentifier(siteTrustDomain),
              case let .string(registrationURLText)? = values["registration_url"],
              let registrationURL = URL(string: registrationURLText),
              Self.matchesRegistrationEndpoint(
                  registrationURL,
                  authorityOrigins: authorityOrigins
              ),
              case let .string(ceremonyID)? = values["app_attest_ceremony_id_b64url"],
              Self.decodeCanonicalBase64URL(ceremonyID, exactLength: 16) != nil,
              case let .string(challengeDigestB64URL)? = values["app_attest_challenge_digest_b64url"],
              let challengeDigest = Self.decodeCanonicalBase64URL(
                  challengeDigestB64URL,
                  exactLength: 32
              ),
              let correlation = Self.optionalCorrelation(
                  values["correlation_b64url"],
                  required: requireCorrelation
              ),
              case let .number(expiryText)? = values["expires_at_unix_millis"],
              let expiresAtUnixMillis = UInt64(expiryText),
              expiresAtUnixMillis > nowUnixMillis,
              expiresAtUnixMillis - nowUnixMillis <= Self.maximumLifetimeMillis
        else { throw PlatformFailure.qrPayloadUnsupported }

        self.reference = reference
        self.correlation = correlation
        self.siteTrustDomain = siteTrustDomain
        self.registrationURL = registrationURL
        self.appAttestCeremonyIDB64URL = ceremonyID
        self.appAttestChallengeDigest = challengeDigest
        self.expiresAtUnixMillis = expiresAtUnixMillis
    }

    private static func validIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                || ($0 >= 97 && $0 <= 122) || [45, 46, 58, 95].contains($0)
        }
    }

    private static func decodeCanonicalBase64URL(_ value: String, exactLength: Int) -> Data? {
        guard !value.isEmpty,
              value.utf8.allSatisfy({
                  ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                      || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95
              }), value.count % 4 != 1
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

    private static func optionalCorrelation(
        _ value: StrictJSONObject.Value?, required: Bool
    ) -> Data?? {
        guard let value else { return required ? nil : .some(nil) }
        guard case let .string(encoded) = value,
              let decoded = decodeCanonicalBase64URL(encoded, exactLength: 32)
        else { return nil }
        return .some(decoded)
    }

    private static func matchesRegistrationEndpoint(
        _ value: URL,
        authorityOrigins: [URL]
    ) -> Bool {
        MonasSiteRootDelegationTransport.matchesAuthority(
            value,
            origins: authorityOrigins,
            expectedPath: MonasSiteRootGenesisEndpointV1.registrationPath
        ) || (authorityOrigins.contains(where: {
            $0.absoluteString == MonasSiteRootGenesisBrokerEndpointV1.origin
        }) && MonasSiteRootDelegationTransport.matchesAuthority(
            value,
            origin: URL(string: MonasSiteRootGenesisBrokerEndpointV1.origin)!,
            expectedPath: MonasSiteRootGenesisBrokerEndpointV1.registrationPath
        ))
    }
}

/// The only first-device registration endpoint. It is fixed rather than QR
/// selected and always protected by the build-time Monas SPKI pin.
enum MonasSiteRootGenesisEndpointV1 {
    static let registrationPath = "/auth/pistis/site-root-genesis/v1/register"
}

/// Fixed, customer-neutral first-install broker endpoints. The broker is a
/// relay only: it never becomes a Site Root authority and never supplies a
/// host for the iPhone to select.
enum MonasSiteRootGenesisBrokerEndpointV1 {
    static let origin = "https://install.mnemosyne.co.uk"
    static let registrationSchema =
        "mnemosyne.monas.first-install-broker.site-root-genesis-registration.v1"
    static let registrationPath =
        "/api/first-install/v1/pistis/site-root-genesis/registration"
    static let purpose = "site-root-genesis"
    static let delegationPollSchema =
        "mnemosyne.monas.first-install-broker.site-root-genesis-delegation-poll.v1"
    static let delegationPollPath =
        "/api/first-install/v1/pistis/site-root-genesis/delegations"
    static let completionSchema =
        "mnemosyne.monas.first-install-broker.site-root-genesis-completion.v1"
    static let completionPath =
        "/api/first-install/v1/pistis/site-root-genesis/completions"
    static let proofSchema =
        "mnemosyne.monas.first-install-broker.site-root-genesis-completion.v1"
    static let proofPath =
        "/api/first-install/v1/pistis/site-root-genesis/completions"
    static let completionPollSchema =
        "mnemosyne.monas.first-install-broker.site-root-genesis-completion-poll.v1"
    static let diagnosticsSchema =
        "mnemosyne.monas.first-install-broker.site-root-genesis-diagnostics.v1"
    static let diagnosticsPath =
        "/api/first-install/v1/pistis/site-root-genesis/diagnostics"
    static let responseSchema = "mnemosyne.monas.first-install-broker.response.v1"
    static let maximumRegistrationBytes = 12 * 1024
    static let maximumDelegationBytes = 12 * 1024
    static let maximumProofBytes = 4 * 1024
    static let maximumPollAttempts = 300
    /// Poll count is a protocol safety ceiling. The transport also enforces
    /// this wall-clock bound so slow or unreachable requests cannot strand an
    /// attended ceremony for minutes.
    static let maximumPollDurationSeconds: TimeInterval = 30
}

/// Typed, public-only first-device registration. Neither this object nor its
/// response contains a private key, session, cookie, token, or local identity.
struct SiteRootGenesisRegistrationRequestV1: Sendable {
    let presentation: SiteRootGenesisRegistrationPresentationV1
    let siteRootKey: SiteRootKeyRegistrationV1
    let appAttestRegistration: AppleAppAttestRegistrationEnvelope
}

/// Monas returns a delegation only after atomically consuming the nonce-bound
/// registration. The caller must then use the existing detached proof flow.
protocol MonasSiteRootGenesisRegistering: Sendable {
    func registerGenesis(_ request: SiteRootGenesisRegistrationRequestV1) async throws
        -> SiteRootDelegationPresentationV1
}

protocol MonasSiteRootCeremonyTransport: MonasSiteRootDelegationSubmitting,
    MonasSiteRootGenesisRegistering
{
    /// The first configured, app-signed origin against which an initial QR is
    /// displayed. `nil` means the production authority is unavailable.
    var genesisAuthorityOrigin: URL? { get }
    var genesisAuthorityOrigins: [URL] { get }
    var requiresGenesisCorrelation: Bool { get }

    /// Best-effort redacted diagnostics for the attended first-device route.
    /// Implementations must never make event delivery a prerequisite for the
    /// protected ceremony.
    func uploadOnboardingEvent(_ event: OnboardingEvent, correlation: Data) async throws
}

extension MonasSiteRootCeremonyTransport {
    var genesisAuthorityOrigins: [URL] {
        genesisAuthorityOrigin.map { [$0] } ?? []
    }

    var requiresGenesisCorrelation: Bool { false }

    func uploadOnboardingEvent(_: OnboardingEvent, correlation _: Data) async throws {
        throw PlatformFailure.onboardingEventUploadUnavailable
    }
}

struct MonasSiteRootGenesisRegistrationRequest: Encodable {
    let schema = "monas.site-root-genesis-registration.v1"
    let reference: String
    let siteRootKey: SiteRootKey
    let appAttestRegistration: AppleAppAttestRegistrationEnvelope

    enum CodingKeys: String, CodingKey {
        case schema, reference
        case siteRootKey = "site_root_key"
        case appAttestRegistration = "app_attest_registration"
    }

    init(_ request: SiteRootGenesisRegistrationRequestV1) {
        reference = request.presentation.reference
        siteRootKey = SiteRootKey(request.siteRootKey)
        appAttestRegistration = request.appAttestRegistration
    }

    struct SiteRootKey: Encodable {
        let schema: String
        let deviceKeyID: String
        let publicKeyCompressedSEC1Base64URL: String
        let secureEnclaveAttestation: String

        enum CodingKeys: String, CodingKey {
            case schema
            case deviceKeyID = "device_key_id"
            case publicKeyCompressedSEC1Base64URL = "public_key_compressed_sec1_base64url"
            case secureEnclaveAttestation = "secure_enclave_attestation"
        }

        init(_ value: SiteRootKeyRegistrationV1) {
            schema = value.schema
            deviceKeyID = value.deviceKeyID
            publicKeyCompressedSEC1Base64URL = value.publicKeyCompressedSEC1
                .base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
            secureEnclaveAttestation = value.secureEnclaveAttestation
        }
    }
}

/// Fixed-origin relay envelope for the existing typed genesis registration.
/// The broker receives only public registration material and opaque rendezvous
/// values; it does not receive a customer host or a private key.
struct MonasSiteRootGenesisBrokerRegistrationRequest: Encodable {
    let schema = MonasSiteRootGenesisBrokerEndpointV1.registrationSchema
    let purpose = MonasSiteRootGenesisBrokerEndpointV1.purpose
    let reference: String
    let correlationB64URL: String
    let registrationRequestB64URL: String

    enum CodingKeys: String, CodingKey {
        case schema, purpose, reference
        case correlationB64URL = "correlation_b64url"
        case registrationRequestB64URL = "registration_request_b64url"
    }

    init(_ request: SiteRootGenesisRegistrationRequestV1) throws {
        guard let correlation = request.presentation.correlation else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        reference = request.presentation.reference
        correlationB64URL = Self.base64URL(correlation)
        let payload = try JSONEncoder().encode(MonasSiteRootGenesisRegistrationRequest(request))
        registrationRequestB64URL = Self.base64URL(payload)
    }

    private static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

struct MonasSiteRootGenesisBrokerDelegationPollRequest: Encodable {
    let schema = MonasSiteRootGenesisBrokerEndpointV1.delegationPollSchema
    let purpose = MonasSiteRootGenesisBrokerEndpointV1.purpose
    let correlationB64URL: String

    enum CodingKeys: String, CodingKey {
        case schema, purpose
        case correlationB64URL = "correlation_b64url"
    }

    init(correlation: Data) {
        self.correlationB64URL = Self.base64URL(correlation)
    }

    private static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// Fixed-origin relay envelope for the existing static Site Root completion.
/// The nested completion remains opaque canonical bytes to the broker.
struct MonasSiteRootGenesisBrokerProofRequest: Encodable {
    let schema = MonasSiteRootGenesisBrokerEndpointV1.proofSchema
    let purpose = MonasSiteRootGenesisBrokerEndpointV1.purpose
    let correlationB64URL: String
    let proofB64URL: String

    enum CodingKeys: String, CodingKey {
        case schema, purpose
        case correlationB64URL = "correlation_b64url"
        case proofB64URL = "proof_b64url"
    }

    init(_ submission: SiteRootDelegationSubmissionV1, correlation: Data) throws {
        self.correlationB64URL = Self.base64URL(correlation)
        let completion = try MonasSiteRootGenesisStaticCompletion(
            submission: submission
        )
        proofB64URL = Self.base64URL(
            try JSONEncoder().encode(completion)
        )
    }

    private static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

struct MonasSiteRootGenesisStaticCompletion: Encodable {
    let schema: String
    let reference: String
    let delegation: JSONValue
    let coseSign1Base64URL: String

    enum CodingKeys: String, CodingKey {
        case schema, reference, delegation
        case coseSign1Base64URL = "cose_sign1_base64url"
    }

    init(submission: SiteRootDelegationSubmissionV1) throws {
        schema = submission.schema
        reference = submission.reference
        delegation = try JSONDecoder().decode(
            JSONValue.self, from: submission.canonicalDelegationJSON
        )
        coseSign1Base64URL = submission.coseSign1Base64URL
    }
}

struct MonasSiteRootGenesisRegistrationResult {
    private static let schema = "monas.site-root-genesis-registration-result.v1"
    private static let maximumResponseBytes = 90_000

    let presentation: SiteRootDelegationPresentationV1

    init(
        data: Data,
        request: SiteRootGenesisRegistrationRequestV1,
        authorityOrigin: URL
    ) throws {
        try self.init(
            data: data,
            request: request,
            authorityOrigins: [authorityOrigin]
        )
    }

    init(
        data: Data,
        request: SiteRootGenesisRegistrationRequestV1,
        authorityOrigins: [URL],
        expectedSubmitPath: String = MonasSiteRootDelegationEndpointV1.submitPath,
        correlation: Data? = nil
    ) throws {
        let values = try StrictJSONObject(data: data, maximumBytes: Self.maximumResponseBytes).values
        let required: Set<String> = [
            "schema", "canonical_delegation_base64url", "device_key_id",
            "site_trust_domain", "submit_url", "reference",
        ]
        guard Set(values.keys) == required,
              case let .string(schema)? = values["schema"], schema == Self.schema,
              case let .string(encodedDelegation)? = values["canonical_delegation_base64url"],
              let canonicalDelegation = Self.decodeBase64URL(encodedDelegation),
              case let .string(deviceKeyID)? = values["device_key_id"],
              deviceKeyID == request.siteRootKey.deviceKeyID,
              case let .string(siteTrustDomain)? = values["site_trust_domain"],
              siteTrustDomain == request.presentation.siteTrustDomain,
              case let .string(submitURLText)? = values["submit_url"],
              let submitURL = URL(string: submitURLText),
              MonasSiteRootDelegationTransport.matchesAuthority(
                  submitURL,
                  origins: authorityOrigins,
                  expectedPath: expectedSubmitPath
              ),
              case let .string(reference)? = values["reference"],
              reference == request.presentation.reference
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        presentation = try SiteRootDelegationPresentationV1(
            canonicalDelegationJSON: canonicalDelegation,
            deviceKeyID: deviceKeyID,
            siteTrustDomain: siteTrustDomain,
            submitURL: submitURL,
            reference: reference,
            expectedSubmitPath: expectedSubmitPath,
            correlation: correlation
        )
    }

    /// Parses the host-produced delegation facts but deliberately replaces
    /// its customer submit URL with the fixed broker completion endpoint.
    /// The host URL is never used as an iPhone routing decision.
    init(
        brokerData data: Data,
        request: SiteRootGenesisRegistrationRequestV1,
        brokerProofURL: URL,
        correlation: Data
    ) throws {
        let values = try StrictJSONObject(data: data, maximumBytes: Self.maximumResponseBytes).values
        let required: Set<String> = [
            "schema", "canonical_delegation_base64url", "device_key_id",
            "site_trust_domain", "submit_url", "reference",
        ]
        guard Set(values.keys) == required,
              case let .string(schema)? = values["schema"], schema == Self.schema,
              case let .string(encodedDelegation)? = values["canonical_delegation_base64url"],
              let canonicalDelegation = Self.decodeBase64URL(encodedDelegation),
              case let .string(deviceKeyID)? = values["device_key_id"],
              deviceKeyID == request.siteRootKey.deviceKeyID,
              case let .string(siteTrustDomain)? = values["site_trust_domain"],
              siteTrustDomain == request.presentation.siteTrustDomain,
              case let .string(submitURLText)? = values["submit_url"],
              let submitURL = URL(string: submitURLText),
              submitURL.scheme == "https",
              submitURL.host != nil,
              submitURL.user == nil,
              submitURL.password == nil,
              submitURL.path == MonasSiteRootDelegationEndpointV1.submitPath,
              submitURL.query == nil,
              submitURL.fragment == nil,
              case let .string(reference)? = values["reference"],
              reference == request.presentation.reference,
              MonasSiteRootDelegationTransport.matchesAuthority(
                  brokerProofURL,
                  origin: URL(string: MonasSiteRootGenesisBrokerEndpointV1.origin)!,
                  expectedPath: MonasSiteRootGenesisBrokerEndpointV1.proofPath
              )
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        presentation = try SiteRootDelegationPresentationV1(
            canonicalDelegationJSON: canonicalDelegation,
            deviceKeyID: deviceKeyID,
            siteTrustDomain: siteTrustDomain,
            submitURL: brokerProofURL,
            reference: reference,
            expectedSubmitPath: MonasSiteRootGenesisBrokerEndpointV1.proofPath,
            correlation: correlation
        )
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        guard !value.isEmpty,
              value.utf8.allSatisfy({
                  ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                      || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95
              }), value.count % 4 != 1
        else { return nil }
        let padding = String(repeating: "=", count: (4 - value.count % 4) % 4)
        return Data(base64Encoded: value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + padding)
    }
}
