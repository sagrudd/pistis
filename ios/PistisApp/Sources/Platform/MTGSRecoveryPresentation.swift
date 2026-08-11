import Foundation

/// One owner-attended, one-use invitation to resume a retained MTGS dispatch.
///
/// The QR carries only a server-owned App Attest challenge. It cannot select a
/// verifier or submission route: both the HTTPS origin and its SPKI are fixed
/// by the installed Pistis application and the assertion uses the fixed Monas
/// recovery endpoint.
struct MTGSRecoveryPresentationV1: Sendable, Equatable {
    static let schema = "monas.site-trust-mtgs-recovery-presentation.v1"
    static let audience = "monas:site-trust:mtgs-recovery:v1"
    static let maximumPayloadLength = 8_192
    static let maximumLifetimeSeconds: UInt64 = 900

    let reference: String
    let siteTrustDomain: String
    let authorityOrigin: URL
    let ceremonyID: Data
    let challengeDigest: Data
    let keyID: Data
    let expiresAtUnixSeconds: UInt64

    init(qrText: String, pinnedAuthorityOrigin: URL, nowUnixSeconds: UInt64) throws {
        guard qrText.utf8.count <= Self.maximumPayloadLength,
              let data = qrText.data(using: .utf8)
        else { throw PlatformFailure.qrPayloadUnsupported }
        let object: StrictJSONObject
        do {
            object = try StrictJSONObject(data: data, maximumBytes: Self.maximumPayloadLength)
        } catch {
            throw PlatformFailure.qrPayloadUnsupported
        }
        let required: Set<String> = [
            "schema", "audience", "reference", "site_trust_domain", "authority_origin",
            "ceremony_id_b64url", "challenge_digest_b64url", "app_identifier",
            "key_id_b64url", "issued_at_unix_seconds", "expires_at_unix_seconds",
        ]
        guard Set(object.values.keys) == required,
              case let .string(schema)? = object.values["schema"], schema == Self.schema,
              case let .string(audience)? = object.values["audience"], audience == Self.audience,
              case let .string(reference)? = object.values["reference"],
              Self.validIdentifier(reference, maximum: 128),
              case let .string(domain)? = object.values["site_trust_domain"],
              Self.validIdentifier(domain, maximum: 255),
              case let .string(originText)? = object.values["authority_origin"],
              let origin = URL(string: originText),
              Self.sameCanonicalOrigin(origin, pinnedAuthorityOrigin),
              case let .string(ceremonyText)? = object.values["ceremony_id_b64url"],
              let ceremony = Self.decode(ceremonyText, count: 16),
              case let .string(hashText)? = object.values["challenge_digest_b64url"],
              let hash = Self.decode(hashText, count: 32),
              case let .string(appIdentifier)? = object.values["app_identifier"],
              appIdentifier == AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
              case let .string(keyText)? = object.values["key_id_b64url"],
              let key = Self.decode(keyText, count: 32),
              case let .number(issuedText)? = object.values["issued_at_unix_seconds"],
              let issued = UInt64(issuedText), issued <= nowUnixSeconds,
              case let .number(expiresText)? = object.values["expires_at_unix_seconds"],
              let expires = UInt64(expiresText), nowUnixSeconds < expires,
              expires >= issued, expires - issued <= Self.maximumLifetimeSeconds
        else { throw PlatformFailure.qrPayloadUnsupported }
        self.reference = reference
        self.siteTrustDomain = domain
        self.authorityOrigin = origin
        self.ceremonyID = ceremony
        self.challengeDigest = hash
        self.keyID = key
        self.expiresAtUnixSeconds = expires
    }

    private static func sameCanonicalOrigin(_ candidate: URL, _ pinned: URL) -> Bool {
        candidate.scheme == "https" && candidate.user == nil && candidate.password == nil
            && candidate.path.isEmpty && candidate.query == nil && candidate.fragment == nil
            && candidate.absoluteString == pinned.absoluteString
    }

    private static func validIdentifier(_ value: String, maximum: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximum && value.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
                || [45, 46, 58, 95].contains($0)
        }
    }

    private static func decode(_ value: String, count: Int) -> Data? {
        guard !value.contains("="), value.count % 4 != 1, value.utf8.allSatisfy({ byte in
            (48...57).contains(byte) || (65...90).contains(byte)
                || (97...122).contains(byte) || byte == 45 || byte == 95
        }) else { return nil }
        let standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let data = Data(base64Encoded: standard), data.count == count,
              !data.allSatisfy({ $0 == 0 }),
              data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "") == value
        else { return nil }
        return data
    }
}
