import Foundation

/// Strict decoder for the sole terminal Monas custody-presentation response.
///
/// Monas may return this body only from the already pinned App Attest
/// assertion transaction after it durably retains the matching Monas session
/// and receives the custody-owned presentation through its fixed
/// Thesaurophylax peer. It is not a browser document, URL parameter, QR
/// payload, cookie, bearer token, local file, account, password, or fallback.
struct MonasRetainedCustodyPresentationResponseV1 {
    static let schema = "monas.retained-iphone-custody-presentation-relay.v1"
    static let maximumLifetimeSeconds: UInt64 = 300

    let presentation: IphoneMediatedCustodyRewrapPresentationV1

    init(data: Data, nowUnixSeconds: UInt64) throws {
        let response: WireResponse
        do {
            response = try JSONDecoder().decode(WireResponse.self, from: data)
        } catch {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        guard response.schema == Self.schema,
              response.expiresAtUnixSeconds > nowUnixSeconds,
              response.expiresAtUnixSeconds - nowUnixSeconds <= Self.maximumLifetimeSeconds,
              let correlation = Self.decodeCanonicalBase64URL(response.correlationB64URL, exact: 16),
              let canonicalChallenge = Self.decodeCanonicalBase64URL(
                  response.canonicalChallengeB64URL, maximum: 4_096
              ),
              let expectedEd25519PublicKey = Self.decodeCanonicalBase64URL(
                  response.expectedEd25519PublicKeyB64URL, exact: 32
              ),
              let encryptedRecordDigest = Self.decodeCanonicalBase64URL(
                  response.encryptedRecordDigestB64URL, exact: 32
              ),
              let existingHostPublic = Self.decodeCanonicalBase64URL(
                  response.existingHostPublicSEC1B64URL, exact: 33
              ),
              let encryptedRecord = Self.decodeCanonicalBase64URL(
                  response.existingEncryptedRecordB64URL, range: 28 ... 4_096
              ),
              let freshHostPublic = Self.decodeCanonicalBase64URL(
                  response.freshHostPublicSEC1B64URL, exact: 33)
        else { throw PlatformFailure.custodyRewrapUnavailable }
        presentation = try IphoneMediatedCustodyRewrapPresentationV1(
            correlation: correlation,
            canonicalChallenge: canonicalChallenge,
            siteTrustDomain: response.siteTrustDomain,
            keyGeneration: response.keyGeneration,
            deviceKeyID: response.deviceKeyID,
            expectedEd25519PublicKey: expectedEd25519PublicKey,
            encryptedRecordDigest: encryptedRecordDigest,
            currentRevocationGeneration: response.currentRevocationGeneration,
            delegationSerial: response.delegationSerial,
            expiresAtUnixSeconds: response.expiresAtUnixSeconds,
            existingHostEphemeralPublicSEC1: existingHostPublic,
            existingEncryptedRecord: encryptedRecord,
            freshHostEphemeralPublicSEC1: freshHostPublic
        )
    }

    private struct WireResponse: Decodable {
        let schema: String
        let correlationB64URL: String
        let canonicalChallengeB64URL: String
        let siteTrustDomain: String
        let keyGeneration: String
        let deviceKeyID: String
        let expectedEd25519PublicKeyB64URL: String
        let encryptedRecordDigestB64URL: String
        let currentRevocationGeneration: UInt64
        let delegationSerial: String
        let expiresAtUnixSeconds: UInt64
        let existingHostPublicSEC1B64URL: String
        let existingEncryptedRecordB64URL: String
        let freshHostPublicSEC1B64URL: String

        private enum CodingKeys: String, CodingKey, CaseIterable {
            case schema
            case correlationB64URL = "correlation_b64url"
            case canonicalChallengeB64URL = "canonical_challenge_b64url"
            case siteTrustDomain = "site_trust_domain"
            case keyGeneration = "key_generation"
            case deviceKeyID = "device_key_id"
            case expectedEd25519PublicKeyB64URL = "expected_ed25519_public_key_b64url"
            case encryptedRecordDigestB64URL = "encrypted_record_digest_b64url"
            case currentRevocationGeneration = "current_revocation_generation"
            case delegationSerial = "delegation_serial"
            case expiresAtUnixSeconds = "expires_at_unix_seconds"
            case existingHostPublicSEC1B64URL = "existing_host_public_sec1_b64url"
            case existingEncryptedRecordB64URL = "existing_encrypted_record_b64url"
            case freshHostPublicSEC1B64URL = "fresh_host_public_sec1_b64url"
        }

        init(from decoder: any Decoder) throws {
            let keys = try decoder.container(keyedBy: DynamicKey.self)
            guard Set(keys.allKeys.map(\.stringValue))
                == Set(CodingKeys.allCases.map(\.rawValue))
            else {
                throw DecodingError.dataCorrupted(
                    .init(codingPath: decoder.codingPath, debugDescription: "unexpected custody relay fields")
                )
            }
            let values = try decoder.container(keyedBy: CodingKeys.self)
            schema = try values.decode(String.self, forKey: .schema)
            correlationB64URL = try values.decode(String.self, forKey: .correlationB64URL)
            canonicalChallengeB64URL = try values.decode(String.self, forKey: .canonicalChallengeB64URL)
            siteTrustDomain = try values.decode(String.self, forKey: .siteTrustDomain)
            keyGeneration = try values.decode(String.self, forKey: .keyGeneration)
            deviceKeyID = try values.decode(String.self, forKey: .deviceKeyID)
            expectedEd25519PublicKeyB64URL = try values.decode(String.self, forKey: .expectedEd25519PublicKeyB64URL)
            encryptedRecordDigestB64URL = try values.decode(String.self, forKey: .encryptedRecordDigestB64URL)
            currentRevocationGeneration = try values.decode(UInt64.self, forKey: .currentRevocationGeneration)
            delegationSerial = try values.decode(String.self, forKey: .delegationSerial)
            expiresAtUnixSeconds = try values.decode(UInt64.self, forKey: .expiresAtUnixSeconds)
            existingHostPublicSEC1B64URL = try values.decode(String.self, forKey: .existingHostPublicSEC1B64URL)
            existingEncryptedRecordB64URL = try values.decode(String.self, forKey: .existingEncryptedRecordB64URL)
            freshHostPublicSEC1B64URL = try values.decode(String.self, forKey: .freshHostPublicSEC1B64URL)
        }
    }

    private static func decodeCanonicalBase64URL(
        _ value: String,
        exact: Int
    ) -> Data? {
        guard let decoded = decodeCanonicalBase64URL(value, maximum: exact), decoded.count == exact
        else { return nil }
        return decoded
    }

    private static func decodeCanonicalBase64URL(
        _ value: String,
        range: ClosedRange<Int>
    ) -> Data? {
        guard let decoded = decodeCanonicalBase64URL(value, maximum: range.upperBound),
              range.contains(decoded.count)
        else { return nil }
        return decoded
    }

    private static func decodeCanonicalBase64URL(_ value: String, maximum: Int) -> Data? {
        guard !value.isEmpty,
              value.utf8.allSatisfy({ byte in
                  (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
                      || (byte >= 48 && byte <= 57) || byte == 45 || byte == 95
              })
        else { return nil }
        let padded = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let decoded = Data(base64Encoded: padded), !decoded.isEmpty, decoded.count <= maximum,
              canonicalBase64URL(decoded) == value
        else { return nil }
        return decoded
    }

    private static func canonicalBase64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// Exact Monas HTTP envelope for one opaque Thesaurophylax custody submission.
/// It can be constructed only from the iPhone's transient producer output;
/// neither this type nor its transport accepts caller-selected authority.
struct MonasRetainedCustodyRewrapSubmissionV1: Encodable {
    static let schema = "monas.retained-iphone-custody-rewrap-submission.v1"

    let schema = Self.schema
    let correlationB64URL: String
    let canonicalChallengeB64URL: String
    let deviceKeyID: String
    let delegationSerial: String
    let siteTrustDomain: String
    let purpose: String
    let detachedCOSESign1B64URL: String
    let rewrappedCiphertextB64URL: String

    enum CodingKeys: String, CodingKey {
        case schema
        case correlationB64URL = "correlation_b64url"
        case canonicalChallengeB64URL = "canonical_challenge_b64url"
        case deviceKeyID = "device_key_id"
        case delegationSerial = "delegation_serial"
        case siteTrustDomain = "site_trust_domain"
        case purpose
        case detachedCOSESign1B64URL = "detached_cose_sign1_b64url"
        case rewrappedCiphertextB64URL = "rewrapped_ciphertext_b64url"
    }

    init(_ submission: IphoneMediatedCustodyRewrapSubmissionV1) {
        correlationB64URL = Self.base64URL(submission.correlation)
        canonicalChallengeB64URL = Self.base64URL(submission.canonicalPayload)
        deviceKeyID = submission.deviceKeyID
        delegationSerial = submission.delegationSerial
        siteTrustDomain = submission.siteTrustDomain
        purpose = submission.purpose
        detachedCOSESign1B64URL = Self.base64URL(submission.coseSign1)
        rewrappedCiphertextB64URL = Self.base64URL(submission.rewrappedCiphertext)
    }

    private static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private struct DynamicKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}
