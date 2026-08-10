import CryptoKit
import XCTest

@testable import Pistis

final class FirstAuthorityCustodyRotationV2Tests: XCTestCase {
    func testHostEnvelopeUsesAcceptedThesaurophylaxPortableWrapProfile() {
        XCTAssertEqual(
            SecureEnclaveFirstAuthorityCustodyProducerV2.hostEnvelopeInfo,
            Data("mnemosyne:thesaurophylax:portable-wrap:v1".utf8)
        )
    }

    func testRotationTranscriptMatchesThesaurophylaxFixture() throws {
        let presentation = try fixturePresentation()
        let transcript = try presentation.canonicalTranscript()

        XCTAssertEqual(
            transcript.hexadecimal,
            "00000038746865736175726f7068796c61782e7069737469732d66697273742d6465766963652d617574686f726974792d726f746174696f6e2e7632000000100101010101010101010101010101010100000007736974652d76320000000d67656e65726174696f6e2d7632000000096465766963652d763200000021026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29600000020030303030303030303030303030303030303030303030303030303030303030300000008000000000000000100000021036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2960000002004040404040404040404040404040404040404040404040404040404040404040000002005050505050505050505050505050505050505050505050505050505050505050000002006060606060606060606060606060606060606060606060606060606060606060000002007070707070707070707070707070707070707070707070707070707070707070000000d64656c65676174696f6e2d7632000000080000000000000064"
        )
        XCTAssertEqual(
            Data(SHA256.hash(data: transcript)).hexadecimal,
            "a9181232d7cf4b737e565cedbf917c6f02915d8060a92301d824f2e2e19bc9c3"
        )
    }

    func testPurposeAndEveryServerBindingAffectTranscript() throws {
        let original = try fixturePresentation().canonicalTranscript()
        let changed = try FirstAuthorityRotationPresentationV2(
            correlation: Data(repeating: 1, count: 16), identity: fixtureIdentity(),
            hostEphemeralPublicSEC1: validPublicKey(),
            legacyRecordSHA256: Data(repeating: 4, count: 32),
            installationBindingSHA256: Data(repeating: 5, count: 32),
            appAttestAcceptanceSHA256: Data(repeating: 6, count: 32),
            siteRootProofSHA256: Data(repeating: 8, count: 32),
            delegationSerial: "delegation-v2", expiresAtUnixSeconds: 100
        ).canonicalTranscript()
        XCTAssertNotEqual(original, changed)

        let recovery = try FirstAuthorityRecoveryPresentationV2(
            correlation: Data(repeating: 1, count: 16), identity: fixtureIdentity(),
            hostEphemeralPublicSEC1: validPublicKey(),
            encryptedRecordSHA256: Data(repeating: 8, count: 32),
            authorityContextSHA256: Data(repeating: 9, count: 32),
            encryptedRecord: Data(repeating: 10, count: 40),
            delegationSerial: "delegation-v2", expiresAtUnixSeconds: 100
        ).canonicalTranscript()
        XCTAssertNotEqual(original, recovery)
        let purpose = Data(FirstAuthorityCustodyPurposeV2.recovery.utf8)
        var expectedPrefix = Data()
        expectedPrefix.append(contentsOf: withUnsafeBytes(
            of: UInt32(purpose.count).bigEndian, Array.init
        ))
        expectedPrefix.append(purpose)
        XCTAssertTrue(recovery.starts(with: expectedPrefix))
    }

    func testIdentityRejectsZeroRevocationAndMalformedCommitment() throws {
        XCTAssertThrowsError(try FirstAuthorityCustodyIdentityV2(
            siteTrustDomain: "site-v2", custodyGeneration: "generation-v2",
            deviceKeyID: "device-v2", enrolledDevicePublicSEC1: enrolledPublicKey(),
            recoverySeedEd25519PublicKey: Data(repeating: 3, count: 32),
            revocationGeneration: 0
        ))
        XCTAssertThrowsError(try FirstAuthorityCustodyIdentityV2(
            siteTrustDomain: "site-v2", custodyGeneration: "generation-v2",
            deviceKeyID: "device-v2", enrolledDevicePublicSEC1: validPublicKey(),
            recoverySeedEd25519PublicKey: Data(repeating: 0, count: 32),
            revocationGeneration: 1
        ))
    }

    func testSeedCiphertextRequiresExactAAD() throws {
        let key = SymmetricKey(data: Data(repeating: 0x33, count: 32))
        var seed = Data(repeating: 0x55, count: 32)
        defer { seed.resetBytes(in: seed.startIndex ..< seed.endIndex) }
        let aad = Data(repeating: 0x44, count: 32)
        let ciphertext = try SecureEnclaveFirstAuthorityCustodyProducerV2.seal(
            seed, key: key, aad: aad
        )
        XCTAssertEqual(ciphertext.count, 60)
        XCTAssertEqual(
            try SecureEnclaveFirstAuthorityCustodyProducerV2.open(
                ciphertext, key: key, aad: aad
            ), seed
        )
        XCTAssertThrowsError(try SecureEnclaveFirstAuthorityCustodyProducerV2.open(
            ciphertext, key: key, aad: Data(repeating: 0x45, count: 32)
        ))
    }

    func testStrictMonasPresentationReconstructsCrossLanguageTranscript() throws {
        let commitment = FirstAuthorityCustodySeedCommitmentV2(
            deviceKeyID: "device-v2", enrolledDevicePublicSEC1: enrolledPublicKey(),
            recoverySeedEd25519PublicKey: Data(repeating: 3, count: 32)
        )
        let data = try wirePresentationData()
        let value = try FirstAuthorityCustodyRotationV2Wire.presentation(
            data: data, expectedCommitment: commitment, nowUnixSeconds: 99
        )
        XCTAssertEqual(try value.canonicalTranscript(), try fixturePresentation().canonicalTranscript())

        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        object["cookie"] = "forbidden"
        XCTAssertThrowsError(try FirstAuthorityCustodyRotationV2Wire.presentation(
            data: JSONSerialization.data(withJSONObject: object),
            expectedCommitment: commitment, nowUnixSeconds: 99
        ))
        object.removeValue(forKey: "cookie")
        object["correlation_b64url"] = base64URL(Data(repeating: 1, count: 16)) + "="
        XCTAssertThrowsError(try FirstAuthorityCustodyRotationV2Wire.presentation(
            data: JSONSerialization.data(withJSONObject: object),
            expectedCommitment: commitment, nowUnixSeconds: 99
        ))
        XCTAssertThrowsError(try FirstAuthorityCustodyRotationV2Wire.presentation(
            data: data, expectedCommitment: commitment, nowUnixSeconds: 100
        ))
    }

    func testAcceptedResponseRequiresExactCorrelationAndKeys() throws {
        let correlation = Data(repeating: 1, count: 16)
        let object: [String: Any] = [
            "schema": FirstAuthorityCustodyRotationV2Wire.acceptedSchema,
            "correlation_b64url": base64URL(correlation),
            "authority_descriptor_b64url": base64URL(Data(repeating: 9, count: 64)),
        ]
        let data = try JSONSerialization.data(withJSONObject: object)
        XCTAssertEqual(
            try FirstAuthorityCustodyRotationV2Wire.accepted(
                data: data, expectedCorrelation: correlation
            ).correlation, correlation
        )
        XCTAssertThrowsError(try FirstAuthorityCustodyRotationV2Wire.accepted(
            data: data, expectedCorrelation: Data(repeating: 2, count: 16)
        ))
    }

    func testBeginAndCompleteEncodeOnlyFrozenMonasKeys() throws {
        let begin = try JSONEncoder().encode(FirstAuthorityCustodyRotationV2Wire.Begin(
            FirstAuthorityCustodySeedCommitmentV2(
                deviceKeyID: "device-v2", enrolledDevicePublicSEC1: enrolledPublicKey(),
                recoverySeedEd25519PublicKey: Data(repeating: 3, count: 32)
            )
        ))
        XCTAssertEqual(try jsonKeys(begin), [
            "schema", "recovery_seed_ed25519_public_key_b64url",
        ])
        let complete = try JSONEncoder().encode(FirstAuthorityCustodyRotationV2Wire.Complete(
            FirstAuthorityCustodySubmissionV2(
                correlation: Data(repeating: 1, count: 16),
                detachedCOSESign1: Data(repeating: 2, count: 80),
                rewrappedSeedCiphertext: Data(repeating: 3, count: 60)
            )
        ))
        XCTAssertEqual(try jsonKeys(complete), [
            "schema", "correlation_b64url", "detached_cose_sign1_b64url",
            "rewrapped_seed_ciphertext_b64url",
        ])
    }

    func testRecoveryTranscriptMatchesThesaurophylaxFixture() throws {
        let value = try recoveryFixture()
        let transcript = try value.canonicalTranscript()
        XCTAssertEqual(
            Data(SHA256.hash(data: transcript)).hexadecimal,
            "bc565540e26cd1a185d1dfe88cf3041c6d4df11c1cc1d88993663a19ef8d48a1"
        )
        let commitment = try fixtureIdentity()
        let decoded = try FirstAuthorityCustodyRotationV2Wire.recoveryPresentation(
            data: try recoveryWireData(), expectedDeviceKeyID: commitment.deviceKeyID,
            expectedEnrolledPublicKey: commitment.enrolledDevicePublicSEC1,
            expectedRecoveryCommitment: commitment.recoverySeedEd25519PublicKey,
            nowUnixSeconds: 99
        )
        XCTAssertEqual(try decoded.canonicalTranscript(), transcript)
    }

    func testRecoveryWireIsPurposeSeparatedAndRejectsSubstitution() throws {
        XCTAssertEqual(
            try jsonKeys(JSONEncoder().encode(
                FirstAuthorityCustodyRotationV2Wire.RecoveryBegin()
            )), ["schema"]
        )
        let complete = try JSONEncoder().encode(
            FirstAuthorityCustodyRotationV2Wire.RecoveryComplete(
                FirstAuthorityCustodySubmissionV2(
                    correlation: Data(repeating: 1, count: 16),
                    detachedCOSESign1: Data(repeating: 2, count: 80),
                    rewrappedSeedCiphertext: Data(repeating: 3, count: 60)
                )
            )
        )
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: complete) as? [String: Any])
        XCTAssertEqual(
            object["schema"] as? String,
            FirstAuthorityCustodyRotationV2Wire.recoveryCompleteSchema
        )

        var presentation = try XCTUnwrap(
            JSONSerialization.jsonObject(with: recoveryWireData()) as? [String: Any]
        )
        presentation["schema"] = FirstAuthorityCustodyRotationV2Wire.presentationSchema
        let identity = try fixtureIdentity()
        XCTAssertThrowsError(try FirstAuthorityCustodyRotationV2Wire.recoveryPresentation(
            data: JSONSerialization.data(withJSONObject: presentation),
            expectedDeviceKeyID: identity.deviceKeyID,
            expectedEnrolledPublicKey: identity.enrolledDevicePublicSEC1,
            expectedRecoveryCommitment: identity.recoverySeedEd25519PublicKey,
            nowUnixSeconds: 99
        ))
    }

    private func jsonKeys(_ data: Data) throws -> Set<String> {
        Set(try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any]).keys)
    }

    private func wirePresentationData() throws -> Data {
        let transcript = try fixturePresentation().canonicalTranscript()
        let object: [String: Any] = [
            "schema": FirstAuthorityCustodyRotationV2Wire.presentationSchema,
            "purpose": FirstAuthorityCustodyPurposeV2.rotation,
            "correlation_b64url": base64URL(Data(repeating: 1, count: 16)),
            "canonical_transcript_b64url": base64URL(transcript),
            "site_trust_domain_id": "site-v2",
            "custody_generation": "generation-v2",
            "device_key_id": "device-v2",
            "enrolled_device_public_sec1_b64url": base64URL(enrolledPublicKey()),
            "recovery_seed_ed25519_public_key_b64url": base64URL(Data(repeating: 3, count: 32)),
            "revocation_generation": 1,
            "host_ephemeral_public_sec1_b64url": base64URL(validPublicKey()),
            "legacy_record_sha256_b64url": base64URL(Data(repeating: 4, count: 32)),
            "installation_binding_sha256_b64url": base64URL(Data(repeating: 5, count: 32)),
            "app_attest_acceptance_sha256_b64url": base64URL(Data(repeating: 6, count: 32)),
            "site_root_proof_sha256_b64url": base64URL(Data(repeating: 7, count: 32)),
            "delegation_serial": "delegation-v2",
            "expires_at_unix_seconds": 100,
        ]
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private func recoveryFixture() throws -> FirstAuthorityRecoveryPresentationV2 {
        try FirstAuthorityRecoveryPresentationV2(
            correlation: Data(repeating: 1, count: 16), identity: fixtureIdentity(),
            hostEphemeralPublicSEC1: enrolledPublicKey(),
            encryptedRecordSHA256: Data(repeating: 8, count: 32),
            authorityContextSHA256: Data(repeating: 9, count: 32),
            encryptedRecord: Data(repeating: 10, count: 40),
            delegationSerial: "delegation-v2", expiresAtUnixSeconds: 100
        )
    }

    private func recoveryWireData() throws -> Data {
        let value = try recoveryFixture()
        let object: [String: Any] = [
            "schema": FirstAuthorityCustodyRotationV2Wire.recoveryPresentationSchema,
            "purpose": FirstAuthorityCustodyPurposeV2.recovery,
            "correlation_b64url": base64URL(value.correlation),
            "canonical_transcript_b64url": base64URL(try value.canonicalTranscript()),
            "site_trust_domain_id": value.identity.siteTrustDomain,
            "custody_generation": value.identity.custodyGeneration,
            "device_key_id": value.identity.deviceKeyID,
            "enrolled_device_public_sec1_b64url": base64URL(
                value.identity.enrolledDevicePublicSEC1
            ),
            "recovery_seed_ed25519_public_key_b64url": base64URL(
                value.identity.recoverySeedEd25519PublicKey
            ),
            "revocation_generation": value.identity.revocationGeneration,
            "host_ephemeral_public_sec1_b64url": base64URL(value.hostEphemeralPublicSEC1),
            "encrypted_record_sha256_b64url": base64URL(value.encryptedRecordSHA256),
            "authority_context_sha256_b64url": base64URL(value.authorityContextSHA256),
            "encrypted_record_b64url": base64URL(value.encryptedRecord),
            "delegation_serial": value.delegationSerial,
            "expires_at_unix_seconds": value.expiresAtUnixSeconds,
        ]
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private func base64URL(_ value: Data) -> String {
        FirstAuthorityCustodyRotationV2Wire.base64URL(value)
    }

    private func fixturePresentation() throws -> FirstAuthorityRotationPresentationV2 {
        FirstAuthorityRotationPresentationV2(
            correlation: Data(repeating: 1, count: 16), identity: try fixtureIdentity(),
            hostEphemeralPublicSEC1: validPublicKey(),
            legacyRecordSHA256: Data(repeating: 4, count: 32),
            installationBindingSHA256: Data(repeating: 5, count: 32),
            appAttestAcceptanceSHA256: Data(repeating: 6, count: 32),
            siteRootProofSHA256: Data(repeating: 7, count: 32),
            delegationSerial: "delegation-v2", expiresAtUnixSeconds: 100
        )
    }

    private func fixtureIdentity() throws -> FirstAuthorityCustodyIdentityV2 {
        try FirstAuthorityCustodyIdentityV2(
            siteTrustDomain: "site-v2", custodyGeneration: "generation-v2",
            deviceKeyID: "device-v2", enrolledDevicePublicSEC1: enrolledPublicKey(),
            recoverySeedEd25519PublicKey: Data(repeating: 3, count: 32),
            revocationGeneration: 1
        )
    }

    private func validPublicKey() -> Data {
        Data(hexadecimal: "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")!
    }

    private func enrolledPublicKey() -> Data {
        Data(hexadecimal: "026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")!
    }
}

private extension Data {
    var hexadecimal: String { map { String(format: "%02x", $0) }.joined() }

    init?(hexadecimal: String) {
        guard hexadecimal.count.isMultiple(of: 2) else { return nil }
        var value = Data()
        var index = hexadecimal.startIndex
        while index < hexadecimal.endIndex {
            let next = hexadecimal.index(index, offsetBy: 2)
            guard let byte = UInt8(hexadecimal[index ..< next], radix: 16) else { return nil }
            value.append(byte)
            index = next
        }
        self = value
    }
}
