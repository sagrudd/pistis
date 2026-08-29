import Foundation

enum BaseCampVaultMigrationRouteV1 {
    static let qrSchema = "monas.basecamp-vault-migration-qr.v1"
    static let presentationSchema = "monas.basecamp-vault-migration-presentation.v1"
    static let submissionSchema = "monas.basecamp-vault-migration-submission.v1"
    static let pagePath = "/settings/basecamp-vault-migration"
    static let presentationPath = "/v1/pistis/basecamp-vault-migration/presentation"
    static let submissionPath = "/v1/pistis/basecamp-vault-migration/submit"
    static let maximumJSONBytes = 16_384
}

/// Deliberately non-authorising QR discriminator for the fixed migration
/// route. It contains no endpoint origin, challenge, proof, ciphertext,
/// reference or capability. The retained installation and its pinned origin
/// remain the only authority for the subsequent fixed-path request.
struct BaseCampVaultMigrationQRV1: Equatable, Sendable {
    init(qrText: String) throws {
        guard let data = qrText.data(using: .utf8), data.count <= 1_024 else {
            throw PlatformFailure.qrPayloadUnsupported
        }
        let values = try StrictJSONObject(data: data, maximumBytes: 1_024).values
        guard Set(values.keys) == ["schema", "purpose", "recipient", "presentation_path"],
              case let .string(schema)? = values["schema"],
              schema == BaseCampVaultMigrationRouteV1.qrSchema,
              case let .string(purpose)? = values["purpose"],
              purpose == BaseCampVaultMigrationProfileV1.purpose,
              case let .string(recipient)? = values["recipient"],
              recipient == BaseCampVaultMigrationProfileV1.recipient,
              case let .string(path)? = values["presentation_path"],
              path == BaseCampVaultMigrationRouteV1.presentationPath
        else { throw PlatformFailure.qrPayloadUnsupported }
    }
}

struct BaseCampVaultMigrationPresentationWireV1: Sendable {
    let presentation: BaseCampVaultMigrationPresentationV1

    init(
        data: Data,
        expectedDeviceKeyID: String,
        expectedRevocationGeneration: UInt64,
        nowUnixSeconds: UInt64
    ) throws {
        let keys: Set<String> = [
            "schema", "correlation_b64url", "canonical_challenge_b64url",
            "fresh_host_public_sec1_b64url", "site_trust_domain", "key_generation",
            "device_key_id", "expected_ed25519_public_key_b64url",
            "encrypted_record_digest_b64url", "current_revocation_generation",
            "delegation_serial", "expires_at_unix_seconds",
            "existing_host_public_sec1_b64url", "existing_encrypted_record_b64url",
        ]
        let object = try StrictJSONObject(
            data: data, maximumBytes: BaseCampVaultMigrationRouteV1.maximumJSONBytes
        ).values
        guard Set(object.keys) == keys else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let wire = try JSONDecoder().decode(Wire.self, from: data)
        guard wire.schema == BaseCampVaultMigrationRouteV1.presentationSchema,
              let correlation = Self.base64URL(wire.correlationB64URL, exact: 16),
              let challenge = Self.base64URL(wire.canonicalChallengeB64URL, range: 1 ... 4_096),
              let freshHost = Self.base64URL(wire.freshHostPublicSEC1B64URL, exact: 33),
              let expectedPublic = Self.base64URL(
                wire.expectedEd25519PublicKeyB64URL, exact: 32
              ),
              let digest = Self.base64URL(wire.encryptedRecordDigestB64URL, exact: 32),
              let existingHost = Self.base64URL(
                wire.existingHostPublicSEC1B64URL, exact: 33
              ),
              let record = Self.base64URL(wire.existingEncryptedRecordB64URL, exact: 60)
        else { throw PlatformFailure.custodyRewrapUnavailable }
        // The retained signed installation stores the authority origin and TLS
        // SPKI, not a separately authorising Site Trust Domain. `data` has
        // already crossed that fail-closed pinned transport boundary. Treat
        // its Site Trust Domain as an authority claim and require it to match
        // the complete signed canonical challenge byte-for-byte below. The
        // device ID and revocation generation remain independent local inputs.
        presentation = try BaseCampVaultMigrationPresentationV1(
            correlation: correlation,
            canonicalChallenge: challenge,
            freshHostPublicSEC1: freshHost,
            siteTrustDomain: wire.siteTrustDomain,
            keyGeneration: wire.keyGeneration,
            deviceKeyID: wire.deviceKeyID,
            expectedEd25519PublicKey: expectedPublic,
            encryptedRecordDigest: digest,
            currentRevocationGeneration: wire.currentRevocationGeneration,
            delegationSerial: wire.delegationSerial,
            expiresAtUnixSeconds: wire.expiresAtUnixSeconds,
            existingHostPublicSEC1: existingHost,
            existingEncryptedRecord: record,
            expectedSiteTrustDomain: wire.siteTrustDomain,
            expectedDeviceKeyID: expectedDeviceKeyID,
            expectedRevocationGeneration: expectedRevocationGeneration,
            nowUnixSeconds: nowUnixSeconds
        )
    }

    private struct Wire: Decodable {
        let schema: String
        let correlationB64URL: String
        let canonicalChallengeB64URL: String
        let freshHostPublicSEC1B64URL: String
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

        enum CodingKeys: String, CodingKey {
            case schema
            case correlationB64URL = "correlation_b64url"
            case canonicalChallengeB64URL = "canonical_challenge_b64url"
            case freshHostPublicSEC1B64URL = "fresh_host_public_sec1_b64url"
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
        }
    }

    private static func base64URL(_ value: String, exact: Int) -> Data? {
        base64URL(value, range: exact ... exact)
    }

    private static func base64URL(_ value: String, range: ClosedRange<Int>) -> Data? {
        guard !value.isEmpty, !value.contains("="), value.utf8.allSatisfy({ byte in
            (48 ... 57).contains(byte) || (65 ... 90).contains(byte)
                || (97 ... 122).contains(byte) || byte == 45 || byte == 95
        }) else { return nil }
        let standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let decoded = Data(base64Encoded: standard), range.contains(decoded.count),
              encode(decoded) == value
        else { return nil }
        return decoded
    }

    static func encode(_ value: Data) -> String {
        value.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

struct BaseCampVaultMigrationSubmissionWireV1: Encodable, Sendable {
    let schema = BaseCampVaultMigrationRouteV1.submissionSchema
    let correlationB64URL: String
    let canonicalChallengeB64URL: String
    let deviceKeyID: String
    let delegationSerial: String
    let siteTrustDomain: String
    let purpose: String
    let detachedCOSESign1B64URL: String
    let rewrappedCiphertextB64URL: String

    init(_ value: IphoneMediatedCustodyRewrapSubmissionV1) throws {
        guard value.purpose == BaseCampVaultMigrationProfileV1.purpose,
              value.correlation.count == 16,
              value.canonicalPayload.starts(with: BaseCampVaultMigrationProfileV1.challengeSchema),
              value.rewrappedCiphertext.count == 60,
              !value.coseSign1.isEmpty
        else { throw PlatformFailure.custodyRewrapUnavailable }
        correlationB64URL = BaseCampVaultMigrationPresentationWireV1.encode(value.correlation)
        canonicalChallengeB64URL = BaseCampVaultMigrationPresentationWireV1.encode(
            value.canonicalPayload
        )
        deviceKeyID = value.deviceKeyID
        delegationSerial = value.delegationSerial
        siteTrustDomain = value.siteTrustDomain
        purpose = value.purpose
        detachedCOSESign1B64URL = BaseCampVaultMigrationPresentationWireV1.encode(
            value.coseSign1
        )
        rewrappedCiphertextB64URL = BaseCampVaultMigrationPresentationWireV1.encode(
            value.rewrappedCiphertext
        )
    }

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
}

enum BaseCampVaultSuccessorRotationRouteV1 {
    static let qrSchema = "monas.basecamp-vault-successor-rotation-qr.v1"
    static let presentationSchema = "monas.basecamp-vault-successor-rotation-presentation.v1"
    static let submissionSchema = "monas.basecamp-vault-successor-rotation-submission.v1"
    static let pagePath = "/settings/basecamp-vault-unlock"
    static let presentationPath = "/v1/pistis/basecamp-vault-unlock/presentation"
    static let submissionPath = "/v1/pistis/basecamp-vault-unlock/submit"
    static let maximumJSONBytes = 16_384
}

struct BaseCampVaultSuccessorRotationQRV1: Equatable, Sendable {
    init(qrText: String) throws {
        guard let data = qrText.data(using: .utf8), data.count <= 1_024 else {
            throw PlatformFailure.qrPayloadUnsupported
        }
        let values = try StrictJSONObject(data: data, maximumBytes: 1_024).values
        guard Set(values.keys) == ["schema", "purpose", "recipient", "presentation_path"],
              case let .string(schema)? = values["schema"],
              schema == BaseCampVaultSuccessorRotationRouteV1.qrSchema,
              case let .string(purpose)? = values["purpose"],
              purpose == BaseCampVaultSuccessorRotationProfileV1.purpose,
              case let .string(recipient)? = values["recipient"],
              recipient == BaseCampVaultSuccessorRotationProfileV1.recipient,
              case let .string(path)? = values["presentation_path"],
              path == BaseCampVaultSuccessorRotationRouteV1.presentationPath
        else { throw PlatformFailure.qrPayloadUnsupported }
    }
}

struct BaseCampVaultSuccessorPresentationWireV1: Sendable {
    let presentation: BaseCampVaultSuccessorRotationPresentationV1

    init(
        data: Data,
        expectedDeviceKeyID: String,
        expectedRevocationGeneration: UInt64,
        nowUnixSeconds: UInt64
    ) throws {
        let keys: Set<String> = [
            "schema", "correlation_b64url", "canonical_challenge_b64url",
            "fresh_host_public_sec1_b64url", "site_trust_domain", "key_generation",
            "device_key_id", "expected_ed25519_public_key_b64url",
            "encrypted_record_digest_b64url", "current_revocation_generation",
            "delegation_serial", "expires_at_unix_seconds",
            "existing_host_public_sec1_b64url", "existing_encrypted_record_b64url",
        ]
        let object = try StrictJSONObject(
            data: data, maximumBytes: BaseCampVaultSuccessorRotationRouteV1.maximumJSONBytes
        ).values
        guard Set(object.keys) == keys else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let wire = try JSONDecoder().decode(Wire.self, from: data)
        guard wire.schema == BaseCampVaultSuccessorRotationRouteV1.presentationSchema,
              let correlation = Self.decode(wire.correlationB64URL, exact: 16),
              let challenge = Self.decode(wire.canonicalChallengeB64URL, range: 1 ... 4_096),
              let freshHost = Self.decode(wire.freshHostPublicSEC1B64URL, exact: 33),
              let expectedPublic = Self.decode(
                wire.expectedEd25519PublicKeyB64URL, exact: 32
              ),
              let digest = Self.decode(wire.encryptedRecordDigestB64URL, exact: 32),
              let existingHost = Self.decode(
                wire.existingHostPublicSEC1B64URL, exact: 33
              ),
              let record = Self.decode(wire.existingEncryptedRecordB64URL, exact: 60)
        else { throw PlatformFailure.custodyRewrapUnavailable }
        // As for migration, the Site Trust Domain is a claim made through the
        // retained origin/SPKI boundary and is cross-bound to the signed
        // canonical challenge. The Site Root ID and revocation generation are
        // independently derived from retained device state by the coordinator.
        presentation = try BaseCampVaultSuccessorRotationPresentationV1(
            correlation: correlation,
            canonicalChallenge: challenge,
            freshHostPublicSEC1: freshHost,
            siteTrustDomain: wire.siteTrustDomain,
            successorGeneration: wire.keyGeneration,
            deviceKeyID: wire.deviceKeyID,
            expectedEd25519PublicKey: expectedPublic,
            encryptedRecordDigest: digest,
            currentRevocationGeneration: wire.currentRevocationGeneration,
            delegationSerial: wire.delegationSerial,
            expiresAtUnixSeconds: wire.expiresAtUnixSeconds,
            existingHostPublicSEC1: existingHost,
            existingEncryptedRecord: record,
            expectedSiteTrustDomain: wire.siteTrustDomain,
            expectedDeviceKeyID: expectedDeviceKeyID,
            expectedRevocationGeneration: expectedRevocationGeneration,
            nowUnixSeconds: nowUnixSeconds
        )
    }

    private struct Wire: Decodable {
        let schema: String
        let correlationB64URL: String
        let canonicalChallengeB64URL: String
        let freshHostPublicSEC1B64URL: String
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
        enum CodingKeys: String, CodingKey {
            case schema
            case correlationB64URL = "correlation_b64url"
            case canonicalChallengeB64URL = "canonical_challenge_b64url"
            case freshHostPublicSEC1B64URL = "fresh_host_public_sec1_b64url"
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
        }
    }

    private static func decode(_ value: String, exact: Int) -> Data? {
        decode(value, range: exact ... exact)
    }

    private static func decode(_ value: String, range: ClosedRange<Int>) -> Data? {
        guard !value.isEmpty, !value.contains("="), value.utf8.allSatisfy({ byte in
            (48 ... 57).contains(byte) || (65 ... 90).contains(byte)
                || (97 ... 122).contains(byte) || byte == 45 || byte == 95
        }) else { return nil }
        let standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let decoded = Data(base64Encoded: standard), range.contains(decoded.count),
              BaseCampVaultMigrationPresentationWireV1.encode(decoded) == value
        else { return nil }
        return decoded
    }
}

struct BaseCampVaultSuccessorSubmissionWireV1: Encodable, Sendable {
    let schema = BaseCampVaultSuccessorRotationRouteV1.submissionSchema
    let correlationB64URL: String
    let canonicalChallengeB64URL: String
    let deviceKeyID: String
    let delegationSerial: String
    let siteTrustDomain: String
    let purpose: String
    let detachedCOSESign1B64URL: String
    let rewrappedCiphertextB64URL: String

    init(_ value: IphoneMediatedCustodyRewrapSubmissionV1) throws {
        guard value.purpose == BaseCampVaultSuccessorRotationProfileV1.purpose,
              value.correlation.count == 16,
              value.canonicalPayload.starts(
                with: BaseCampVaultSuccessorRotationProfileV1.challengeSchema
              ),
              value.rewrappedCiphertext.count == 60,
              !value.coseSign1.isEmpty
        else { throw PlatformFailure.custodyRewrapUnavailable }
        correlationB64URL = BaseCampVaultMigrationPresentationWireV1.encode(value.correlation)
        canonicalChallengeB64URL = BaseCampVaultMigrationPresentationWireV1.encode(
            value.canonicalPayload
        )
        deviceKeyID = value.deviceKeyID
        delegationSerial = value.delegationSerial
        siteTrustDomain = value.siteTrustDomain
        purpose = value.purpose
        detachedCOSESign1B64URL = BaseCampVaultMigrationPresentationWireV1.encode(
            value.coseSign1
        )
        rewrappedCiphertextB64URL = BaseCampVaultMigrationPresentationWireV1.encode(
            value.rewrappedCiphertext
        )
    }

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
}
