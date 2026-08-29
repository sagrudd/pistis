import CryptoKit
import XCTest

@testable import Pistis

final class BaseCampVaultMigrationV1Tests: XCTestCase {
    func testAcceptedNineteenFieldMigrationVectorAndReview() throws {
        let fixture = try Fixture()
        let presentation = try fixture.presentation()

        XCTAssertEqual(presentation.correlation, fixture.correlation)
        XCTAssertEqual(presentation.enrolledDevicePublicSEC1, fixture.devicePublic)
        XCTAssertEqual(presentation.vaultDigest, fixture.vaultDigest)
        XCTAssertEqual(presentation.sourceDigest, fixture.sourceDigest)
        XCTAssertEqual(presentation.inventoryDigest, fixture.inventoryDigest)
        XCTAssertEqual(presentation.issuedAtUnixSeconds, fixture.issuedAt)
        XCTAssertEqual(
            presentation.review,
            BaseCampVaultMigrationReviewV1(
                operation: "Migrate the existing Base Camp vault credential",
                siteTrustDomain: fixture.site,
                purpose: "basecamp-vault-passphrase-delivery-v1",
                recipient: "mnemosyne-expedition-basecamp.service",
                custodyGeneration: fixture.generation,
                deviceKeyID: fixture.deviceID,
                expiresAtUnixSeconds: fixture.expiresAt
            )
        )
    }

    func testEveryTagPositionAndEveryFieldLengthAreCanonical() throws {
        let fixture = try Fixture()
        let fields = fixture.fields
        XCTAssertEqual(fields.count, 19)

        for index in fields.indices {
            var wrongTag = fields
            wrongTag[index].tag = wrongTag[index].tag == 255 ? 254 : wrongTag[index].tag + 1
            XCTAssertThrowsError(
                try fixture.presentation(challenge: fixture.challenge(wrongTag)),
                "accepted wrong tag at field \(index + 1)"
            )

            var empty = fields
            empty[index].value = Data()
            XCTAssertThrowsError(
                try fixture.presentation(challenge: fixture.challenge(empty)),
                "accepted empty field \(index + 1)"
            )
        }
    }

    func testSchemaTrailingOversizeAndAlternativeProfilesDeny() throws {
        let fixture = try Fixture()
        var trailing = fixture.canonicalChallenge
        trailing.append(0)
        XCTAssertThrowsError(try fixture.presentation(challenge: trailing))

        var generic = Data("thesaurophylax.iphone-mediated-custody-rewrap.v1\0".utf8)
        generic.append(fixture.canonicalChallenge.dropFirst(
            BaseCampVaultMigrationProfileV1.challengeSchema.count
        ))
        XCTAssertThrowsError(try fixture.presentation(challenge: generic))

        var receipt = Data("thesaurophylax.site-root-bundle-receipt-rewrap.v1\0".utf8)
        receipt.append(fixture.canonicalChallenge.dropFirst(
            BaseCampVaultMigrationProfileV1.challengeSchema.count
        ))
        XCTAssertThrowsError(try fixture.presentation(challenge: receipt))
        XCTAssertThrowsError(try fixture.presentation(
            challenge: Data(repeating: 1, count: 4_097)
        ))
    }

    func testEveryDuplicatedOrFixedCanonicalValueIsCrossBound() throws {
        let fixture = try Fixture()
        for index in fixture.fields.indices {
            // The three source-evidence digests occur only in the signed
            // challenge; Pistis displays them as server-observed evidence but
            // has no independent local value against which to compare them.
            if [6, 7, 8].contains(index) { continue }
            var mutated = fixture.fields
            mutated[index].value[mutated[index].value.startIndex] ^= 1
            XCTAssertThrowsError(
                try fixture.presentation(challenge: fixture.challenge(mutated)),
                "accepted changed canonical field \(index + 1)"
            )
        }
    }

    func testTrustedContextCarriageAndFreshnessDriftDeny() throws {
        let fixture = try Fixture()
        XCTAssertThrowsError(try fixture.presentation(expectedSite: "foreign-site"))
        XCTAssertThrowsError(try fixture.presentation(expectedDevice: "site-root-foreign"))
        XCTAssertThrowsError(try fixture.presentation(expectedRevocation: 8))
        XCTAssertThrowsError(try fixture.presentation(now: fixture.issuedAt - 1))
        XCTAssertThrowsError(try fixture.presentation(now: fixture.expiresAt))

        XCTAssertThrowsError(try fixture.presentation(correlation: Data(repeating: 4, count: 16)))
        XCTAssertThrowsError(try fixture.presentation(site: "foreign-site"))
        XCTAssertThrowsError(try fixture.presentation(generation: "basecamp-vault-2"))
        XCTAssertThrowsError(try fixture.presentation(deviceID: "site-root-foreign"))
        XCTAssertThrowsError(try fixture.presentation(revocation: 8))
        XCTAssertThrowsError(try fixture.presentation(delegation: "delegation-foreign"))
        XCTAssertThrowsError(try fixture.presentation(expiresAt: fixture.expiresAt - 1))
        XCTAssertThrowsError(try fixture.presentation(expectedPublic: Data(repeating: 8, count: 32)))
        XCTAssertThrowsError(try fixture.presentation(recordDigest: Data(repeating: 8, count: 32)))
        XCTAssertThrowsError(try fixture.presentation(existingHost: fixture.freshHostPublic))
        XCTAssertThrowsError(try fixture.presentation(freshHost: fixture.oldHostPublic))
    }

    func testLifetimeP256DigestAndDeviceIdentityRulesDeny() throws {
        var fixture = try Fixture()
        fixture.expiresAt = fixture.issuedAt + 601
        XCTAssertThrowsError(try fixture.presentation())

        fixture = try Fixture()
        var fields = fixture.fields
        fields[6].value = Data(repeating: 0, count: 32)
        XCTAssertThrowsError(try fixture.presentation(challenge: fixture.challenge(fields)))

        fields = fixture.fields
        fields[3].value[0] = 4
        XCTAssertThrowsError(try fixture.presentation(challenge: fixture.challenge(fields)))

        fields = fixture.fields
        fields[18].value = fixture.oldHostPublic
        XCTAssertThrowsError(
            try fixture.presentation(
                challenge: fixture.challenge(fields), freshHost: fixture.oldHostPublic
            )
        )

        fields = fixture.fields
        fields[3].value = fixture.otherDevicePublic
        XCTAssertThrowsError(try fixture.presentation(challenge: fixture.challenge(fields)))
    }

    func testPurposeBoundAADMatchesIndependentEncodingAndNotGenericAAD() throws {
        let fixture = try Fixture()
        let presentation = try fixture.presentation()
        let actual = BaseCampVaultMigrationCryptographicCoreV1.aad(
            presentation, hostPublicSEC1: fixture.oldHostPublic
        )
        XCTAssertEqual(actual, fixture.purposeAAD(host: fixture.oldHostPublic))
        XCTAssertNotEqual(
            actual,
            SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapAADDigest(
                siteTrustDomain: fixture.site,
                keyGeneration: fixture.generation,
                deviceKeyID: fixture.deviceID,
                hostEphemeralPublicSEC1: fixture.oldHostPublic
            )
        )
    }

    func testSimulatorProducerEmitsExactEightFieldSubmissionAndRewrapsSecret() throws {
        let fixture = try Fixture()
        let presentation = try fixture.presentation()
        let submission = try fixture.produce(presentation)

        XCTAssertEqual(submission.correlation, fixture.correlation)
        XCTAssertEqual(submission.canonicalPayload, fixture.canonicalChallenge)
        XCTAssertEqual(submission.deviceKeyID, fixture.deviceID)
        XCTAssertEqual(submission.delegationSerial, fixture.delegation)
        XCTAssertEqual(submission.siteTrustDomain, fixture.site)
        XCTAssertEqual(submission.purpose, BaseCampVaultMigrationProfileV1.purpose)
        XCTAssertFalse(submission.coseSign1.isEmpty)
        XCTAssertEqual(submission.rewrappedCiphertext.count, 60)

        let freshShared = try fixture.deviceAgreement.sharedSecretFromKeyAgreement(
            with: fixture.freshHostPrivate.publicKey
        ).withUnsafeBytes { Data($0) }
        let aad = fixture.purposeAAD(host: fixture.freshHostPublic)
        let key = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
            sharedSecret: freshShared, aadDigest: aad
        )
        XCTAssertEqual(
            try SecureEnclaveIphoneMediatedCustodyRewrapProducer.open(
                submission.rewrappedCiphertext, key: key, aadDigest: aad
            ),
            fixture.secret
        )
    }

    func testSimulatorProducerDeniesForeignDeviceAndPayloadIntegrityDrift() throws {
        let fixture = try Fixture()
        let presentation = try fixture.presentation()
        XCTAssertThrowsError(try BaseCampVaultMigrationCryptographicCoreV1.produce(
            presentation,
            enrolledDevicePublicSEC1: fixture.otherDevicePublic,
            sign: { _ in Data(repeating: 1, count: 64) },
            deriveSharedSecret: { try fixture.shared(with: $0) }
        ))

        let wrong = try Fixture(secretByte: 0x31, expectedSecretByte: 0x32)
        XCTAssertThrowsError(try wrong.produce(try wrong.presentation()))
    }
}

private struct Fixture {
    struct Field {
        var tag: UInt8
        var value: Data
    }

    let site = "site-fixture"
    let generation = "basecamp-vault-1"
    let revocation: UInt64 = 7
    let correlation = Data(repeating: 0x41, count: 16)
    let delegation = "delegation-fixture"
    let issuedAt: UInt64 = 1_000
    var expiresAt: UInt64 = 1_100
    let vaultDigest = Data(repeating: 0x51, count: 32)
    let sourceDigest = Data(repeating: 0x52, count: 32)
    let inventoryDigest = Data(repeating: 0x53, count: 32)
    let deviceSigning: P256.Signing.PrivateKey
    let deviceAgreement: P256.KeyAgreement.PrivateKey
    let otherDeviceAgreement: P256.KeyAgreement.PrivateKey
    let oldHostPrivate: P256.KeyAgreement.PrivateKey
    let freshHostPrivate: P256.KeyAgreement.PrivateKey
    let secret: Data
    let expectedPublic: Data
    let encryptedRecord: Data

    var devicePublic: Data { deviceAgreement.publicKey.compressedRepresentation }
    var otherDevicePublic: Data { otherDeviceAgreement.publicKey.compressedRepresentation }
    var oldHostPublic: Data { oldHostPrivate.publicKey.compressedRepresentation }
    var freshHostPublic: Data { freshHostPrivate.publicKey.compressedRepresentation }
    var deviceID: String {
        "site-root-" + Data(SHA256.hash(data: devicePublic)).hexadecimal
    }
    var recordDigest: Data { Data(SHA256.hash(data: encryptedRecord)) }
    var canonicalChallenge: Data { challenge(fields) }

    var fields: [Field] {
        [
            Field(tag: 1, value: Data(site.utf8)),
            Field(tag: 2, value: Data(generation.utf8)),
            Field(tag: 3, value: Data(deviceID.utf8)),
            Field(tag: 4, value: devicePublic),
            Field(tag: 5, value: revocation.bigEndianData),
            Field(tag: 6, value: correlation),
            Field(tag: 7, value: vaultDigest),
            Field(tag: 8, value: sourceDigest),
            Field(tag: 9, value: inventoryDigest),
            Field(tag: 10, value: recordDigest),
            Field(tag: 11, value: expectedPublic),
            Field(tag: 12, value: oldHostPublic),
            Field(tag: 13, value: Data(BaseCampVaultMigrationProfileV1.purpose.utf8)),
            Field(tag: 14, value: Data(BaseCampVaultMigrationProfileV1.recipient.utf8)),
            Field(tag: 15, value: Data(BaseCampVaultMigrationProfileV1.credentialSocket.utf8)),
            Field(tag: 16, value: Data(delegation.utf8)),
            Field(tag: 17, value: issuedAt.bigEndianData),
            Field(tag: 18, value: expiresAt.bigEndianData),
            Field(tag: 19, value: freshHostPublic),
        ]
    }

    init(secretByte: UInt8 = 0x31, expectedSecretByte: UInt8? = nil) throws {
        let deviceScalar = Data(repeating: 0x09, count: 32)
        deviceSigning = try P256.Signing.PrivateKey(rawRepresentation: deviceScalar)
        deviceAgreement = try P256.KeyAgreement.PrivateKey(rawRepresentation: deviceScalar)
        otherDeviceAgreement = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 0x08, count: 32)
        )
        oldHostPrivate = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 0x02, count: 32)
        )
        freshHostPrivate = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 0x03, count: 32)
        )
        secret = Data(repeating: secretByte, count: 32)
        expectedPublic = try Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(repeating: expectedSecretByte ?? secretByte, count: 32)
        ).publicKey.rawRepresentation

        let oldShared = try deviceAgreement.sharedSecretFromKeyAgreement(
            with: oldHostPrivate.publicKey
        ).withUnsafeBytes { Data($0) }
        var material = Data()
        let derivedDeviceID = "site-root-" + Data(
            SHA256.hash(data: deviceAgreement.publicKey.compressedRepresentation)
        ).hexadecimal
        for value in [
            Data(BaseCampVaultMigrationProfileV1.purpose.utf8), Data(site.utf8),
            Data(generation.utf8), Data(derivedDeviceID.utf8),
            oldHostPrivate.publicKey.compressedRepresentation,
        ] {
            material.append(contentsOf: UInt32(value.count).bigEndianBytes)
            material.append(value)
        }
        let aad = Data(SHA256.hash(data: material))
        let key = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
            sharedSecret: oldShared, aadDigest: aad
        )
        encryptedRecord = try SecureEnclaveIphoneMediatedCustodyRewrapProducer.seal(
            secret, key: key, aadDigest: aad
        )
    }

    func challenge(_ fields: [Field]) -> Data {
        var result = BaseCampVaultMigrationProfileV1.challengeSchema
        for field in fields {
            result.append(field.tag)
            result.append(contentsOf: UInt16(field.value.count).bigEndianBytes)
            result.append(field.value)
        }
        return result
    }

    func purposeAAD(host: Data) -> Data {
        var material = Data()
        for value in [
            Data(BaseCampVaultMigrationProfileV1.purpose.utf8), Data(site.utf8),
            Data(generation.utf8), Data(deviceID.utf8), host,
        ] {
            material.append(contentsOf: UInt32(value.count).bigEndianBytes)
            material.append(value)
        }
        return Data(SHA256.hash(data: material))
    }

    func presentation(
        challenge: Data? = nil,
        correlation: Data? = nil,
        site: String? = nil,
        generation: String? = nil,
        deviceID: String? = nil,
        expectedPublic: Data? = nil,
        recordDigest: Data? = nil,
        revocation: UInt64? = nil,
        delegation: String? = nil,
        expiresAt: UInt64? = nil,
        existingHost: Data? = nil,
        freshHost: Data? = nil,
        expectedSite: String? = nil,
        expectedDevice: String? = nil,
        expectedRevocation: UInt64? = nil,
        now: UInt64? = nil
    ) throws -> BaseCampVaultMigrationPresentationV1 {
        try BaseCampVaultMigrationPresentationV1(
            correlation: correlation ?? self.correlation,
            canonicalChallenge: challenge ?? canonicalChallenge,
            freshHostPublicSEC1: freshHost ?? freshHostPublic,
            siteTrustDomain: site ?? self.site,
            keyGeneration: generation ?? self.generation,
            deviceKeyID: deviceID ?? self.deviceID,
            expectedEd25519PublicKey: expectedPublic ?? self.expectedPublic,
            encryptedRecordDigest: recordDigest ?? self.recordDigest,
            currentRevocationGeneration: revocation ?? self.revocation,
            delegationSerial: delegation ?? self.delegation,
            expiresAtUnixSeconds: expiresAt ?? self.expiresAt,
            existingHostPublicSEC1: existingHost ?? oldHostPublic,
            existingEncryptedRecord: encryptedRecord,
            expectedSiteTrustDomain: expectedSite ?? self.site,
            expectedDeviceKeyID: expectedDevice ?? self.deviceID,
            expectedRevocationGeneration: expectedRevocation ?? self.revocation,
            nowUnixSeconds: now ?? issuedAt + 1
        )
    }

    func shared(with peer: Data) throws -> Data {
        let key = try P256.KeyAgreement.PublicKey(compressedRepresentation: peer)
        return try deviceAgreement.sharedSecretFromKeyAgreement(with: key).withUnsafeBytes {
            Data($0)
        }
    }

    func produce(
        _ presentation: BaseCampVaultMigrationPresentationV1
    ) throws -> IphoneMediatedCustodyRewrapSubmissionV1 {
        try BaseCampVaultMigrationCryptographicCoreV1.produce(
            presentation,
            enrolledDevicePublicSEC1: devicePublic,
            sign: { input in
                try P256Format.rawSignature(
                    fromStrictDER: deviceSigning.signature(for: input).derRepresentation
                )
            },
            deriveSharedSecret: { try shared(with: $0) }
        )
    }
}

private extension Data {
    var hexadecimal: String { map { String(format: "%02x", $0) }.joined() }
}

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] { withUnsafeBytes(of: bigEndian, Array.init) }
    var bigEndianData: Data { Data(bigEndianBytes) }
}
