import Foundation

enum FirstAuthorityCustodyRotationV2Wire {
    static let beginSchema = "monas.first-authority-custody-rotation-begin.v2"
    static let presentationSchema = "monas.first-authority-custody-rotation-presentation.v2"
    static let completeSchema = "monas.first-authority-custody-rotation-complete.v2"
    static let acceptedSchema = "monas.first-authority-custody-rotation-accepted.v2"
    static let recoveryBeginSchema = "monas.first-authority-custody-recovery-begin.v2"
    static let recoveryPresentationSchema =
        "monas.first-authority-custody-recovery-presentation.v2"
    static let recoveryCompleteSchema = "monas.first-authority-custody-recovery-complete.v2"
    static let recoveryAcceptedSchema = "monas.first-authority-custody-recovery-accepted.v2"

    struct RecoveryBegin: Encodable { let schema = recoveryBeginSchema }

    struct Begin: Encodable {
        let schema = beginSchema
        let recoverySeedEd25519PublicKeyB64URL: String

        enum CodingKeys: String, CodingKey {
            case schema
            case recoverySeedEd25519PublicKeyB64URL =
                "recovery_seed_ed25519_public_key_b64url"
        }

        init(_ value: FirstAuthorityCustodySeedCommitmentV2) throws {
            guard value.recoverySeedEd25519PublicKey.count == 32,
                  !value.recoverySeedEd25519PublicKey.allSatisfy({ $0 == 0 })
            else { throw PlatformFailure.custodyRewrapUnavailable }
            recoverySeedEd25519PublicKeyB64URL = Self.base64URL(
                value.recoverySeedEd25519PublicKey
            )
        }
    }

    struct Complete: Encodable {
        let schema = completeSchema
        let correlationB64URL: String
        let detachedCOSESign1B64URL: String
        let rewrappedSeedCiphertextB64URL: String

        enum CodingKeys: String, CodingKey {
            case schema
            case correlationB64URL = "correlation_b64url"
            case detachedCOSESign1B64URL = "detached_cose_sign1_b64url"
            case rewrappedSeedCiphertextB64URL = "rewrapped_seed_ciphertext_b64url"
        }

        init(_ value: FirstAuthorityCustodySubmissionV2) throws {
            guard value.correlation.count == 16,
                  !value.correlation.allSatisfy({ $0 == 0 }),
                  !value.detachedCOSESign1.isEmpty,
                  value.detachedCOSESign1.count <= 4_096,
                  value.rewrappedSeedCiphertext.count == 60
            else { throw PlatformFailure.custodyRewrapUnavailable }
            correlationB64URL = Self.base64URL(value.correlation)
            detachedCOSESign1B64URL = Self.base64URL(value.detachedCOSESign1)
            rewrappedSeedCiphertextB64URL = Self.base64URL(value.rewrappedSeedCiphertext)
        }
    }

    struct RecoveryComplete: Encodable {
        let schema = recoveryCompleteSchema
        let correlationB64URL: String
        let detachedCOSESign1B64URL: String
        let rewrappedSeedCiphertextB64URL: String

        enum CodingKeys: String, CodingKey {
            case schema
            case correlationB64URL = "correlation_b64url"
            case detachedCOSESign1B64URL = "detached_cose_sign1_b64url"
            case rewrappedSeedCiphertextB64URL = "rewrapped_seed_ciphertext_b64url"
        }

        init(_ value: FirstAuthorityCustodySubmissionV2) throws {
            let rotation = try Complete(value)
            correlationB64URL = rotation.correlationB64URL
            detachedCOSESign1B64URL = rotation.detachedCOSESign1B64URL
            rewrappedSeedCiphertextB64URL = rotation.rewrappedSeedCiphertextB64URL
        }
    }

    static func presentation(
        data: Data, expectedCommitment: FirstAuthorityCustodySeedCommitmentV2,
        nowUnixSeconds: UInt64
    ) throws -> FirstAuthorityRotationPresentationV2 {
        let expected = Set([
            "schema", "purpose", "correlation_b64url", "canonical_transcript_b64url",
            "site_trust_domain_id", "custody_generation", "device_key_id",
            "enrolled_device_public_sec1_b64url",
            "recovery_seed_ed25519_public_key_b64url", "revocation_generation",
            "host_ephemeral_public_sec1_b64url", "legacy_record_sha256_b64url",
            "installation_binding_sha256_b64url", "app_attest_acceptance_sha256_b64url",
            "site_root_proof_sha256_b64url", "delegation_serial", "expires_at_unix_seconds",
        ])
        let object = try exactObject(data, keys: expected)
        guard string(object, "schema") == presentationSchema,
              string(object, "purpose") == FirstAuthorityCustodyPurposeV2.rotation,
              let correlation = bytes(object, "correlation_b64url", count: 16),
              let canonical = bytes(object, "canonical_transcript_b64url", maximum: 16_384),
              let site = string(object, "site_trust_domain_id"),
              let generation = string(object, "custody_generation"),
              let deviceKeyID = string(object, "device_key_id"),
              let enrolled = bytes(object, "enrolled_device_public_sec1_b64url", count: 33),
              let commitment = bytes(
                  object, "recovery_seed_ed25519_public_key_b64url", count: 32
              ),
              let revocation = uint64(object, "revocation_generation"),
              let host = bytes(object, "host_ephemeral_public_sec1_b64url", count: 33),
              let legacy = bytes(object, "legacy_record_sha256_b64url", count: 32),
              let installation = bytes(
                  object, "installation_binding_sha256_b64url", count: 32
              ),
              let appAttest = bytes(
                  object, "app_attest_acceptance_sha256_b64url", count: 32
              ),
              let siteRoot = bytes(object, "site_root_proof_sha256_b64url", count: 32),
              let serial = string(object, "delegation_serial"),
              let expiry = uint64(object, "expires_at_unix_seconds"),
              expiry > nowUnixSeconds,
              deviceKeyID == expectedCommitment.deviceKeyID,
              enrolled == expectedCommitment.enrolledDevicePublicSEC1,
              commitment == expectedCommitment.recoverySeedEd25519PublicKey
        else { throw PlatformFailure.custodyRewrapUnavailable }
        let identity = try FirstAuthorityCustodyIdentityV2(
            siteTrustDomain: site, custodyGeneration: generation, deviceKeyID: deviceKeyID,
            enrolledDevicePublicSEC1: enrolled,
            recoverySeedEd25519PublicKey: commitment, revocationGeneration: revocation
        )
        let value = FirstAuthorityRotationPresentationV2(
            correlation: correlation, identity: identity, hostEphemeralPublicSEC1: host,
            legacyRecordSHA256: legacy, installationBindingSHA256: installation,
            appAttestAcceptanceSHA256: appAttest, siteRootProofSHA256: siteRoot,
            delegationSerial: serial, expiresAtUnixSeconds: expiry
        )
        guard try value.canonicalTranscript() == canonical else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        return value
    }

    static func accepted(
        data: Data, expectedCorrelation: Data, schema expectedSchema: String = acceptedSchema
    ) throws -> FirstAuthorityCustodyAcceptedV2 {
        let object = try exactObject(
            data, keys: ["schema", "correlation_b64url", "authority_descriptor_b64url"]
        )
        guard string(object, "schema") == expectedSchema,
              let correlation = bytes(object, "correlation_b64url", count: 16),
              correlation == expectedCorrelation,
              let descriptor = bytes(object, "authority_descriptor_b64url", maximum: 16_384)
        else { throw PlatformFailure.custodyRewrapUnavailable }
        return try FirstAuthorityCustodyAcceptedV2(
            correlation: correlation, authorityDescriptor: descriptor
        )
    }

    static func recoveryPresentation(
        data: Data, expectedDeviceKeyID: String, expectedEnrolledPublicKey: Data,
        expectedRecoveryCommitment: Data, nowUnixSeconds: UInt64
    ) throws -> FirstAuthorityRecoveryPresentationV2 {
        let expected = Set([
            "schema", "purpose", "correlation_b64url", "canonical_transcript_b64url",
            "site_trust_domain_id", "custody_generation", "device_key_id",
            "enrolled_device_public_sec1_b64url",
            "recovery_seed_ed25519_public_key_b64url", "revocation_generation",
            "host_ephemeral_public_sec1_b64url", "encrypted_record_sha256_b64url",
            "authority_context_sha256_b64url", "encrypted_record_b64url",
            "delegation_serial", "expires_at_unix_seconds",
        ])
        let object = try exactObject(data, keys: expected)
        guard string(object, "schema") == recoveryPresentationSchema,
              string(object, "purpose") == FirstAuthorityCustodyPurposeV2.recovery,
              let correlation = bytes(object, "correlation_b64url", count: 16),
              let canonical = bytes(object, "canonical_transcript_b64url", maximum: 16_384),
              let site = string(object, "site_trust_domain_id"),
              let generation = string(object, "custody_generation"),
              let deviceKeyID = string(object, "device_key_id"),
              let enrolled = bytes(object, "enrolled_device_public_sec1_b64url", count: 33),
              let commitment = bytes(
                  object, "recovery_seed_ed25519_public_key_b64url", count: 32
              ),
              let revocation = uint64(object, "revocation_generation"),
              let host = bytes(object, "host_ephemeral_public_sec1_b64url", count: 33),
              let recordDigest = bytes(object, "encrypted_record_sha256_b64url", count: 32),
              let contextDigest = bytes(object, "authority_context_sha256_b64url", count: 32),
              let record = bytes(object, "encrypted_record_b64url", maximum: 4_096),
              let serial = string(object, "delegation_serial"),
              let expiry = uint64(object, "expires_at_unix_seconds"), expiry > nowUnixSeconds,
              deviceKeyID == expectedDeviceKeyID,
              enrolled == expectedEnrolledPublicKey,
              commitment == expectedRecoveryCommitment
        else { throw PlatformFailure.custodyRewrapUnavailable }
        let identity = try FirstAuthorityCustodyIdentityV2(
            siteTrustDomain: site, custodyGeneration: generation, deviceKeyID: deviceKeyID,
            enrolledDevicePublicSEC1: enrolled,
            recoverySeedEd25519PublicKey: commitment, revocationGeneration: revocation
        )
        let value = FirstAuthorityRecoveryPresentationV2(
            correlation: correlation, identity: identity, hostEphemeralPublicSEC1: host,
            encryptedRecordSHA256: recordDigest, authorityContextSHA256: contextDigest,
            encryptedRecord: record, delegationSerial: serial, expiresAtUnixSeconds: expiry
        )
        guard try value.canonicalTranscript() == canonical else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        return value
    }

    private static func exactObject(_ data: Data, keys: Set<String>) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= 32_768,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == keys
        else { throw PlatformFailure.custodyRewrapUnavailable }
        return object
    }

    private static func string(_ object: [String: Any], _ key: String) -> String? {
        guard let value = object[key] as? String, !value.isEmpty else { return nil }
        return value
    }

    private static func uint64(_ object: [String: Any], _ key: String) -> UInt64? {
        guard let number = object[key] as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID()
        else { return nil }
        let value = number.doubleValue
        guard value.isFinite, value >= 0, value.rounded() == value,
              value <= Double(UInt64.max), number.stringValue == String(UInt64(value))
        else { return nil }
        return UInt64(value)
    }

    private static func bytes(
        _ object: [String: Any], _ key: String, count: Int? = nil,
        maximum: Int? = nil
    ) -> Data? {
        guard let encoded = string(object, key), let value = decodeBase64URL(encoded),
              count.map({ value.count == $0 }) ?? true,
              maximum.map({ !value.isEmpty && value.count <= $0 }) ?? true
        else { return nil }
        return value
    }

    static func decodeBase64URL(_ value: String) -> Data? {
        guard !value.isEmpty, !value.contains("="),
              value.utf8.allSatisfy({
                  ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                      || ($0 >= 97 && $0 <= 122) || $0 == 45 || $0 == 95
              })
        else { return nil }
        var standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = standard.count % 4
        guard remainder != 1 else { return nil }
        if remainder != 0 { standard += String(repeating: "=", count: 4 - remainder) }
        guard let decoded = Data(base64Encoded: standard), base64URL(decoded) == value else {
            return nil
        }
        return decoded
    }

    static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private extension FirstAuthorityCustodyRotationV2Wire.Begin {
    static func base64URL(_ value: Data) -> String {
        FirstAuthorityCustodyRotationV2Wire.base64URL(value)
    }
}

private extension FirstAuthorityCustodyRotationV2Wire.Complete {
    static func base64URL(_ value: Data) -> String {
        FirstAuthorityCustodyRotationV2Wire.base64URL(value)
    }
}
