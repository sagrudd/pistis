import CryptoKit
import Foundation

@testable import Pistis

/// Deterministic production-wire evidence for the simulator-only custody gate.
/// Hardware App Attest, Secure Enclave and Face ID results remain explicit
/// inputs in `MonasFirstWebLoginIPhoneSimulatorTests`.
struct MonasFirstWebLoginCustodySimulatorFixture {
    let commitment: FirstAuthorityCustodySeedCommitmentV2
    let presentation: Data
    let accepted: Data

    init(
        mode: FirstAuthorityCustodyModeV2,
        expiresAtUnixSeconds: UInt64
    ) throws {
        let correlation = Data(repeating: 0x41, count: 16)
        let enrolled = Self.publicKey(prefix: 0x02)
        let host = Self.publicKey(prefix: 0x03)
        let recoveryCommitment = Data(repeating: 0x43, count: 32)
        let commitmentValue = FirstAuthorityCustodySeedCommitmentV2(
            deviceKeyID: "candidate-device-v2",
            enrolledDevicePublicSEC1: enrolled,
            recoverySeedEd25519PublicKey: recoveryCommitment
        )
        commitment = commitmentValue
        let identity = try FirstAuthorityCustodyIdentityV2(
            siteTrustDomain: "candidate-site-v2",
            custodyGeneration: "generation-v2",
            deviceKeyID: commitmentValue.deviceKeyID,
            enrolledDevicePublicSEC1: enrolled,
            recoverySeedEd25519PublicKey: recoveryCommitment,
            revocationGeneration: 1
        )

        let object: [String: Any]
        let acceptedSchema: String
        switch mode {
        case .rotation:
            let value = FirstAuthorityRotationPresentationV2(
                correlation: correlation,
                identity: identity,
                hostEphemeralPublicSEC1: host,
                legacyRecordSHA256: Data(repeating: 0x44, count: 32),
                installationBindingSHA256: Data(repeating: 0x45, count: 32),
                appAttestAcceptanceSHA256: Data(repeating: 0x46, count: 32),
                siteRootProofSHA256: Data(repeating: 0x47, count: 32),
                delegationSerial: "delegation-v2",
                expiresAtUnixSeconds: expiresAtUnixSeconds
            )
            object = [
                "schema": FirstAuthorityCustodyRotationV2Wire.presentationSchema,
                "purpose": FirstAuthorityCustodyPurposeV2.rotation,
                "correlation_b64url": Self.b64(correlation),
                "canonical_transcript_b64url": Self.b64(try value.canonicalTranscript()),
                "site_trust_domain_id": identity.siteTrustDomain,
                "custody_generation": identity.custodyGeneration,
                "device_key_id": identity.deviceKeyID,
                "enrolled_device_public_sec1_b64url": Self.b64(enrolled),
                "recovery_seed_ed25519_public_key_b64url": Self.b64(recoveryCommitment),
                "revocation_generation": identity.revocationGeneration,
                "host_ephemeral_public_sec1_b64url": Self.b64(host),
                "legacy_record_sha256_b64url": Self.b64(value.legacyRecordSHA256),
                "installation_binding_sha256_b64url":
                    Self.b64(value.installationBindingSHA256),
                "app_attest_acceptance_sha256_b64url":
                    Self.b64(value.appAttestAcceptanceSHA256),
                "site_root_proof_sha256_b64url": Self.b64(value.siteRootProofSHA256),
                "delegation_serial": value.delegationSerial,
                "expires_at_unix_seconds": value.expiresAtUnixSeconds,
            ]
            acceptedSchema = FirstAuthorityCustodyRotationV2Wire.acceptedSchema
        case .recovery:
            let encryptedRecord = Data(repeating: 0x48, count: 64)
            let value = FirstAuthorityRecoveryPresentationV2(
                correlation: correlation,
                identity: identity,
                hostEphemeralPublicSEC1: host,
                encryptedRecordSHA256: Data(SHA256.hash(data: encryptedRecord)),
                authorityContextSHA256: Data(repeating: 0x49, count: 32),
                encryptedRecord: encryptedRecord,
                delegationSerial: "delegation-v2",
                expiresAtUnixSeconds: expiresAtUnixSeconds
            )
            object = [
                "schema": FirstAuthorityCustodyRotationV2Wire.recoveryPresentationSchema,
                "purpose": FirstAuthorityCustodyPurposeV2.recovery,
                "correlation_b64url": Self.b64(correlation),
                "canonical_transcript_b64url": Self.b64(try value.canonicalTranscript()),
                "site_trust_domain_id": identity.siteTrustDomain,
                "custody_generation": identity.custodyGeneration,
                "device_key_id": identity.deviceKeyID,
                "enrolled_device_public_sec1_b64url": Self.b64(enrolled),
                "recovery_seed_ed25519_public_key_b64url": Self.b64(recoveryCommitment),
                "revocation_generation": identity.revocationGeneration,
                "host_ephemeral_public_sec1_b64url": Self.b64(host),
                "encrypted_record_sha256_b64url": Self.b64(value.encryptedRecordSHA256),
                "authority_context_sha256_b64url": Self.b64(value.authorityContextSHA256),
                "encrypted_record_b64url": Self.b64(encryptedRecord),
                "delegation_serial": value.delegationSerial,
                "expires_at_unix_seconds": value.expiresAtUnixSeconds,
            ]
            acceptedSchema = FirstAuthorityCustodyRotationV2Wire.recoveryAcceptedSchema
        }
        presentation = try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys]
        )
        accepted = try JSONSerialization.data(
            withJSONObject: [
                "schema": acceptedSchema,
                "correlation_b64url": Self.b64(correlation),
                "authority_descriptor_b64url": Self.b64(Data(repeating: 0x50, count: 64)),
            ],
            options: [.sortedKeys]
        )
    }

    private static func publicKey(prefix: UInt8) -> Data {
        Data([prefix])
            + Data([
                0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
                0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
                0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
                0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
            ])
    }

    private static func b64(_ value: Data) -> String {
        FirstAuthorityCustodyRotationV2Wire.base64URL(value)
    }
}

extension MonasFirstWebLoginIPhoneSimulator {
    mutating func observeAuthorityCustodyStatus(
        _ status: MonasSiteRootDelegationTransport.AuthorityCustodyStatusV2
    ) throws {
        try require(.siteX509Committed)
        guard status != .ready else { throw fail(.outOfOrder) }
        authorityCustodyStatus = status
        stage = .authorityCustodyStatusChecked
        evidence.append("production-authority-custody-status-checked")
    }

    mutating func acceptAuthorityCustodyAppAttest(
        _ accepted: Bool,
        observedLifecycle: MonasSiteRootDelegationTransport.AuthorityCustodyStatusV2
    ) throws {
        try require(.authorityCustodyStatusChecked)
        guard accepted else { throw fail(.appAttestDenied) }
        do {
            let transition = try AuthorityCustodyAcceptedAssertionTransitionV2.next(
                after: authorityCustodyStatus ?? .ready,
                observedLifecycle: observedLifecycle
            )
            authorityCustodyStatus = transition.status
        } catch {
            throw fail(.outOfOrder)
        }
        stage = .authorityCustodyAppAttestAccepted
        evidence.append("simulated-authority-custody-app-attest-assertion-accepted")
    }

    mutating func reviewAuthorityCustody(
        fixture: MonasFirstWebLoginCustodySimulatorFixture,
        nowUnixSeconds: UInt64
    ) throws {
        guard
            stage == .authorityCustodyStatusChecked
                || stage == .authorityCustodyAppAttestAccepted
        else { throw fail(.outOfOrder) }
        do {
            switch authorityCustodyStatus {
            case .initialRotationRequired:
                let value = try FirstAuthorityCustodyRotationV2Wire.presentation(
                    data: fixture.presentation,
                    expectedCommitment: fixture.commitment,
                    nowUnixSeconds: nowUnixSeconds
                )
                authorityCustodyCorrelation = value.correlation
                authorityCustodyAcceptedSchema =
                    FirstAuthorityCustodyRotationV2Wire.acceptedSchema
            case .recoveryRequired:
                let value = try FirstAuthorityCustodyRotationV2Wire.recoveryPresentation(
                    data: fixture.presentation,
                    expectedDeviceKeyID: fixture.commitment.deviceKeyID,
                    expectedEnrolledPublicKey: fixture.commitment.enrolledDevicePublicSEC1,
                    expectedRecoveryCommitment:
                        fixture.commitment.recoverySeedEd25519PublicKey,
                    nowUnixSeconds: nowUnixSeconds
                )
                authorityCustodyCorrelation = value.correlation
                authorityCustodyAcceptedSchema =
                    FirstAuthorityCustodyRotationV2Wire.recoveryAcceptedSchema
            default:
                throw Failure.outOfOrder
            }
        } catch let failure as Failure {
            throw fail(failure)
        } catch {
            throw fail(.unsupportedQR)
        }
        stage = .authorityCustodyReviewed
        evidence.append("production-authority-custody-v2-presentation-verified")
    }

    mutating func acceptAuthorityCustodyBiometric(_ accepted: Bool) throws {
        try simulatedBiometric(
            accepted,
            from: .authorityCustodyReviewed,
            to: .authorityCustodyBiometricAccepted,
            evidence: "simulated-authority-custody-biometric-accepted"
        )
    }

    mutating func commitAuthorityCustody(acceptedData: Data) throws {
        try require(.authorityCustodyBiometricAccepted)
        guard let correlation = authorityCustodyCorrelation,
            let acceptedSchema = authorityCustodyAcceptedSchema
        else { throw fail(.outOfOrder) }
        do {
            _ = try FirstAuthorityCustodyRotationV2Wire.accepted(
                data: acceptedData,
                expectedCorrelation: correlation,
                schema: acceptedSchema
            )
        } catch {
            throw fail(.unsupportedQR)
        }
        stage = .authorityCustodyCommitted
        evidence.append("durable-thesaurophylax-authority-signer-ready")
    }
}
