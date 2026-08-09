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
    let siteTrustDomain: String
    let registrationURL: URL
    let appAttestCeremonyIDB64URL: String
    let appAttestChallengeDigest: Data
    let expiresAtUnixMillis: UInt64

    init(qrText: String, authorityOrigin: URL, nowUnixMillis: UInt64) throws {
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
        guard Set(values.keys) == required,
              case let .string(schema)? = values["schema"], schema == Self.schema,
              case let .string(reference)? = values["reference"], Self.validIdentifier(reference),
              case let .string(siteTrustDomain)? = values["site_trust_domain"],
              Self.validIdentifier(siteTrustDomain),
              case let .string(registrationURLText)? = values["registration_url"],
              let registrationURL = URL(string: registrationURLText),
              MonasSiteRootDelegationTransport.matchesAuthority(
                  registrationURL,
                  origin: authorityOrigin,
                  expectedPath: MonasSiteRootGenesisEndpointV1.registrationPath
              ),
              case let .string(ceremonyID)? = values["app_attest_ceremony_id_b64url"],
              Self.decodeCanonicalBase64URL(ceremonyID, exactLength: 16) != nil,
              case let .string(challengeDigestB64URL)? = values["app_attest_challenge_digest_b64url"],
              let challengeDigest = Self.decodeCanonicalBase64URL(
                  challengeDigestB64URL,
                  exactLength: 32
              ),
              case let .number(expiryText)? = values["expires_at_unix_millis"],
              let expiresAtUnixMillis = UInt64(expiryText),
              expiresAtUnixMillis > nowUnixMillis,
              expiresAtUnixMillis - nowUnixMillis <= Self.maximumLifetimeMillis
        else { throw PlatformFailure.qrPayloadUnsupported }

        self.reference = reference
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
}

/// The only first-device registration endpoint. It is fixed rather than QR
/// selected and always protected by the build-time Monas SPKI pin.
enum MonasSiteRootGenesisEndpointV1 {
    static let registrationPath = "/auth/pistis/site-root-genesis/v1/register"
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
    /// The configured, app-signed origin against which an initial QR is
    /// checked. `nil` means the production authority is unavailable.
    var genesisAuthorityOrigin: URL? { get }
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

struct MonasSiteRootGenesisRegistrationResult {
    private static let schema = "monas.site-root-genesis-registration-result.v1"
    private static let maximumResponseBytes = 90_000

    let presentation: SiteRootDelegationPresentationV1

    init(
        data: Data,
        request: SiteRootGenesisRegistrationRequestV1,
        authorityOrigin: URL
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
                  origin: authorityOrigin,
                  expectedPath: MonasSiteRootDelegationEndpointV1.submitPath
              ),
              case let .string(reference)? = values["reference"],
              reference == request.presentation.reference
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        presentation = try SiteRootDelegationPresentationV1(
            canonicalDelegationJSON: canonicalDelegation,
            deviceKeyID: deviceKeyID,
            siteTrustDomain: siteTrustDomain,
            submitURL: submitURL,
            reference: reference
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
