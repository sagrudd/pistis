import CryptoKit
import Foundation

/// Exact purpose-separated constants accepted by Thesaurophylax ADR-0012.
///
/// These are not route, QR or discovery values. They authenticate the
/// canonical challenge and portable-wrap AAD only; a later reviewed Monas
/// integration must select its own fixed transport constants.
enum BaseCampVaultMigrationProfileV1 {
    static let challengeSchema = Data(
        "thesaurophylax.basecamp-vault-custody-provisioning.v1\0".utf8
    )
    static let purpose = "basecamp-vault-passphrase-delivery-v1"
    static let recipient = "mnemosyne-expedition-basecamp.service"
    static let credentialSocket =
        "/run/mnemosyne-thesaurophylax/basecamp-vault-passphrase.sock"
    static let generationPrefix = "basecamp-vault-"
    static let maximumChallengeBytes = 4_096
    static let maximumLifetimeSeconds: UInt64 = 600
    static let presentationFieldCount = 13
    static let submissionFieldCount = 8
}

/// Non-secret evidence that the governed application presentation must show
/// before it asks for an explicit decision and fresh Face ID.
struct BaseCampVaultMigrationReviewV1: Equatable, Sendable {
    let operation: String
    let siteTrustDomain: String
    let purpose: String
    let recipient: String
    let custodyGeneration: String
    let deviceKeyID: String
    let expiresAtUnixSeconds: UInt64
}

/// Strict Pistis projection of the existing thirteen-field THESMIP1 carriage.
///
/// Construction parses the complete nineteen-field Base Camp challenge and
/// cross-checks every duplicated carriage value. Device and revocation
/// expectations come from retained enrolled trust, never from the
/// presentation itself. The wire adapter supplies the Site expectation only
/// after the response crosses the retained origin/SPKI boundary; it exists to
/// require byte-identical outer/challenge claims and is not a second locally
/// persisted Site authority.
/// This type has no decoder, route, URL, QR or persistence surface.
struct BaseCampVaultMigrationPresentationV1: Equatable, Sendable {
    let correlation: Data
    let canonicalChallenge: Data
    let freshHostPublicSEC1: Data
    let siteTrustDomain: String
    let keyGeneration: String
    let deviceKeyID: String
    let expectedEd25519PublicKey: Data
    let encryptedRecordDigest: Data
    let currentRevocationGeneration: UInt64
    let delegationSerial: String
    let expiresAtUnixSeconds: UInt64
    let existingHostPublicSEC1: Data
    let existingEncryptedRecord: Data

    let enrolledDevicePublicSEC1: Data
    let vaultDigest: Data
    let sourceDigest: Data
    let inventoryDigest: Data
    let issuedAtUnixSeconds: UInt64

    var review: BaseCampVaultMigrationReviewV1 {
        BaseCampVaultMigrationReviewV1(
            operation: "Migrate the existing Base Camp vault credential",
            siteTrustDomain: siteTrustDomain,
            purpose: BaseCampVaultMigrationProfileV1.purpose,
            recipient: BaseCampVaultMigrationProfileV1.recipient,
            custodyGeneration: keyGeneration,
            deviceKeyID: deviceKeyID,
            expiresAtUnixSeconds: expiresAtUnixSeconds
        )
    }

    init(
        correlation: Data,
        canonicalChallenge: Data,
        freshHostPublicSEC1: Data,
        siteTrustDomain: String,
        keyGeneration: String,
        deviceKeyID: String,
        expectedEd25519PublicKey: Data,
        encryptedRecordDigest: Data,
        currentRevocationGeneration: UInt64,
        delegationSerial: String,
        expiresAtUnixSeconds: UInt64,
        existingHostPublicSEC1: Data,
        existingEncryptedRecord: Data,
        expectedSiteTrustDomain: String,
        expectedDeviceKeyID: String,
        expectedRevocationGeneration: UInt64,
        nowUnixSeconds: UInt64
    ) throws {
        guard canonicalChallenge.count <= BaseCampVaultMigrationProfileV1.maximumChallengeBytes,
              Self.validIdentifier(siteTrustDomain),
              keyGeneration.hasPrefix(BaseCampVaultMigrationProfileV1.generationPrefix),
              Self.validIdentifier(keyGeneration),
              Self.validIdentifier(deviceKeyID),
              Self.validIdentifier(delegationSerial),
              siteTrustDomain == expectedSiteTrustDomain,
              deviceKeyID == expectedDeviceKeyID,
              currentRevocationGeneration == expectedRevocationGeneration,
              correlation.count == 16,
              !Self.zero(correlation),
              expectedEd25519PublicKey.count == 32,
              !Self.zero(expectedEd25519PublicKey),
              encryptedRecordDigest.count == 32,
              !Self.zero(encryptedRecordDigest),
              existingEncryptedRecord.count == 60,
              Data(SHA256.hash(data: existingEncryptedRecord)) == encryptedRecordDigest,
              Self.canonicalP256(existingHostPublicSEC1),
              Self.canonicalP256(freshHostPublicSEC1),
              existingHostPublicSEC1 != freshHostPublicSEC1
        else { throw PlatformFailure.custodyRewrapUnavailable }

        var fields = try BaseCampVaultMigrationChallengeReaderV1(canonicalChallenge)
        let challengeSite = try fields.identifier(tag: 1)
        let challengeGeneration = try fields.identifier(tag: 2)
        let challengeDevice = try fields.identifier(tag: 3)
        let enrolledDevicePublic = try fields.bytes(tag: 4, exact: 33)
        let challengeRevocation = try fields.uint64(tag: 5)
        let transactionID = try fields.bytes(tag: 6, exact: 16)
        let vaultDigest = try fields.digest(tag: 7)
        let sourceDigest = try fields.digest(tag: 8)
        let inventoryDigest = try fields.digest(tag: 9)
        let stagedDigest = try fields.digest(tag: 10)
        let payloadPublicKey = try fields.bytes(tag: 11, exact: 32)
        let stagedHostPublic = try fields.bytes(tag: 12, exact: 33)
        let purpose = try fields.text(tag: 13, maximum: 128)
        let recipient = try fields.text(tag: 14, maximum: 128)
        let credentialSocket = try fields.text(tag: 15, maximum: 256)
        let challengeDelegation = try fields.identifier(tag: 16)
        let issuedAt = try fields.uint64(tag: 17)
        let challengeExpiry = try fields.uint64(tag: 18)
        let completionHostPublic = try fields.bytes(tag: 19, exact: 33)
        try fields.finish()

        let enrolledDeviceID = "site-root-" + Data(
            SHA256.hash(data: enrolledDevicePublic)
        ).map { String(format: "%02x", $0) }.joined()

        guard challengeSite == siteTrustDomain,
              challengeGeneration == keyGeneration,
              challengeDevice == deviceKeyID,
              Self.canonicalP256(enrolledDevicePublic),
              enrolledDeviceID == deviceKeyID,
              challengeRevocation == currentRevocationGeneration,
              transactionID == correlation,
              stagedDigest == encryptedRecordDigest,
              payloadPublicKey == expectedEd25519PublicKey,
              Self.canonicalP256(stagedHostPublic),
              stagedHostPublic == existingHostPublicSEC1,
              purpose == BaseCampVaultMigrationProfileV1.purpose,
              recipient == BaseCampVaultMigrationProfileV1.recipient,
              credentialSocket == BaseCampVaultMigrationProfileV1.credentialSocket,
              challengeDelegation == delegationSerial,
              issuedAt <= nowUnixSeconds,
              nowUnixSeconds < challengeExpiry,
              issuedAt < challengeExpiry,
              challengeExpiry - issuedAt <= BaseCampVaultMigrationProfileV1.maximumLifetimeSeconds,
              challengeExpiry == expiresAtUnixSeconds,
              Self.canonicalP256(completionHostPublic),
              completionHostPublic == freshHostPublicSEC1,
              completionHostPublic != stagedHostPublic
        else { throw PlatformFailure.custodyRewrapUnavailable }

        self.correlation = correlation
        self.canonicalChallenge = canonicalChallenge
        self.freshHostPublicSEC1 = freshHostPublicSEC1
        self.siteTrustDomain = siteTrustDomain
        self.keyGeneration = keyGeneration
        self.deviceKeyID = deviceKeyID
        self.expectedEd25519PublicKey = expectedEd25519PublicKey
        self.encryptedRecordDigest = encryptedRecordDigest
        self.currentRevocationGeneration = currentRevocationGeneration
        self.delegationSerial = delegationSerial
        self.expiresAtUnixSeconds = expiresAtUnixSeconds
        self.existingHostPublicSEC1 = existingHostPublicSEC1
        self.existingEncryptedRecord = existingEncryptedRecord
        enrolledDevicePublicSEC1 = enrolledDevicePublic
        self.vaultDigest = vaultDigest
        self.sourceDigest = sourceDigest
        self.inventoryDigest = inventoryDigest
        issuedAtUnixSeconds = issuedAt
    }

    private static func validIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value.utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
                || (byte >= 97 && byte <= 122) || [45, 46, 58, 95].contains(byte)
        }
    }

    private static func canonicalP256(_ value: Data) -> Bool {
        guard value.count == 33, value.first == 2 || value.first == 3 else { return false }
        return (try? P256.KeyAgreement.PublicKey(compressedRepresentation: value)) != nil
    }

    private static func zero(_ value: Data) -> Bool {
        value.allSatisfy { $0 == 0 }
    }
}

/// Secure Enclave producer for one reviewed Base Camp migration.
///
/// The caller must first present `presentation.review`, obtain an explicit
/// application-level approval, and then supply one freshly evaluated Face ID
/// context. This API is intentionally incompatible with the ordinary-login
/// coordinator and has no auto-approval entry point.
final class SecureEnclaveBaseCampVaultMigrationProducerV1: @unchecked Sendable {
    private let signer: SecureEnclaveSigner

    init() throws {
        signer = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: "Approve Base Camp vault custody migration"
        )
    }

    func produce(
        _ presentation: BaseCampVaultMigrationPresentationV1,
        using ceremony: FaceIDCeremonyContext
    ) throws -> IphoneMediatedCustodyRewrapSubmissionV1 {
        let publicKey = try signer.publicKey(using: ceremony).compressedSEC1
        return try BaseCampVaultMigrationCryptographicCoreV1.produce(
            presentation,
            enrolledDevicePublicSEC1: publicKey,
            sign: { try signer.sign(message: $0, using: ceremony) },
            deriveSharedSecret: {
                try signer.deriveECDHSharedSecret(
                    peerPublicCompressedSEC1: $0,
                    using: ceremony
                )
            }
        )
    }
}

/// Pure cryptographic composition shared by the Secure Enclave adapter and
/// deterministic simulator conformance tests. Production supplies only
/// Secure Enclave operations; this core creates no key and performs no I/O.
enum BaseCampVaultMigrationCryptographicCoreV1 {
    static func produce(
        _ presentation: BaseCampVaultMigrationPresentationV1,
        enrolledDevicePublicSEC1: Data,
        sign: (Data) throws -> Data,
        deriveSharedSecret: (Data) throws -> Data,
        seal: (Data, SymmetricKey, Data) throws -> Data = {
            try SecureEnclaveIphoneMediatedCustodyRewrapProducer.seal(
                $0, key: $1, aadDigest: $2
            )
        }
    ) throws -> IphoneMediatedCustodyRewrapSubmissionV1 {
        guard enrolledDevicePublicSEC1 == presentation.enrolledDevicePublicSEC1 else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let deviceID = "site-root-" + Data(SHA256.hash(data: enrolledDevicePublicSEC1))
            .map { String(format: "%02x", $0) }.joined()
        guard deviceID == presentation.deviceKeyID else {
            throw PlatformFailure.custodyRewrapUnavailable
        }

        let protected = try DetachedES256Cose.protectedHeaders(kid: presentation.deviceKeyID)
        let structure = try DetachedES256Cose.signatureStructure(
            protected: protected,
            payload: presentation.canonicalChallenge
        )
        let signature = try sign(structure)
        let cose = try DetachedES256Cose.envelope(protected: protected, signature: signature)

        var oldShared = try deriveSharedSecret(presentation.existingHostPublicSEC1)
        defer { zeroize(&oldShared) }
        let oldAAD = aad(
            presentation,
            hostPublicSEC1: presentation.existingHostPublicSEC1
        )
        let oldKey = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
            sharedSecret: oldShared,
            aadDigest: oldAAD
        )
        var secret = try SecureEnclaveIphoneMediatedCustodyRewrapProducer.open(
            presentation.existingEncryptedRecord,
            key: oldKey,
            aadDigest: oldAAD
        )
        defer { zeroize(&secret) }
        guard secret.count == 32,
              let integrityKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: secret),
              integrityKey.publicKey.rawRepresentation == presentation.expectedEd25519PublicKey
        else { throw PlatformFailure.custodyRewrapUnavailable }

        var freshShared = try deriveSharedSecret(presentation.freshHostPublicSEC1)
        defer { zeroize(&freshShared) }
        let freshAAD = aad(
            presentation,
            hostPublicSEC1: presentation.freshHostPublicSEC1
        )
        let freshKey = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
            sharedSecret: freshShared,
            aadDigest: freshAAD
        )
        let ciphertext = try seal(secret, freshKey, freshAAD)
        guard ciphertext.count == 60 else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        return IphoneMediatedCustodyRewrapSubmissionV1(
            correlation: presentation.correlation,
            canonicalPayload: presentation.canonicalChallenge,
            deviceKeyID: presentation.deviceKeyID,
            delegationSerial: presentation.delegationSerial,
            siteTrustDomain: presentation.siteTrustDomain,
            purpose: BaseCampVaultMigrationProfileV1.purpose,
            coseSign1: cose,
            rewrappedCiphertext: ciphertext
        )
    }

    static func aad(
        _ presentation: BaseCampVaultMigrationPresentationV1,
        hostPublicSEC1: Data
    ) -> Data {
        purposeAAD(
            siteTrustDomain: presentation.siteTrustDomain,
            keyGeneration: presentation.keyGeneration,
            deviceKeyID: presentation.deviceKeyID,
            hostPublicSEC1: hostPublicSEC1
        )
    }

    static func purposeAAD(
        siteTrustDomain: String,
        keyGeneration: String,
        deviceKeyID: String,
        hostPublicSEC1: Data
    ) -> Data {
        var material = Data()
        for value in [
            Data(BaseCampVaultMigrationProfileV1.purpose.utf8),
            Data(siteTrustDomain.utf8),
            Data(keyGeneration.utf8),
            Data(deviceKeyID.utf8),
            hostPublicSEC1,
        ] {
            material.append(contentsOf: UInt32(value.count).baseCampBigEndianBytes)
            material.append(value)
        }
        return Data(SHA256.hash(data: material))
    }

    private static func zeroize(_ value: inout Data) {
        guard !value.isEmpty else { return }
        value.resetBytes(in: value.startIndex ..< value.endIndex)
    }
}

private struct BaseCampVaultMigrationChallengeReaderV1 {
    private let data: Data
    private var offset: Int

    init(_ data: Data) throws {
        let schema = BaseCampVaultMigrationProfileV1.challengeSchema
        guard data.count > schema.count,
              data.prefix(schema.count) == schema
        else { throw PlatformFailure.custodyRewrapUnavailable }
        self.data = data
        offset = schema.count
    }

    mutating func identifier(tag: UInt8) throws -> String {
        let value = try text(tag: tag, maximum: 128)
        guard !value.isEmpty, value.utf8.allSatisfy({ byte in
            (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
                || (byte >= 97 && byte <= 122) || [45, 46, 58, 95].contains(byte)
        }) else { throw PlatformFailure.custodyRewrapUnavailable }
        return value
    }

    mutating func text(tag: UInt8, maximum: Int) throws -> String {
        let value = try bytes(tag: tag, range: 1 ... maximum)
        guard let text = String(data: value, encoding: .utf8), Data(text.utf8) == value else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        return text
    }

    mutating func digest(tag: UInt8) throws -> Data {
        let value = try bytes(tag: tag, exact: 32)
        guard !value.allSatisfy({ $0 == 0 }) else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        return value
    }

    mutating func uint64(tag: UInt8) throws -> UInt64 {
        let value = try bytes(tag: tag, exact: 8)
        return value.reduce(0) { ($0 << 8) | UInt64($1) }
    }

    mutating func bytes(tag: UInt8, exact: Int) throws -> Data {
        try bytes(tag: tag, range: exact ... exact)
    }

    mutating func bytes(tag: UInt8, range: ClosedRange<Int>) throws -> Data {
        guard offset + 3 <= data.count,
              data[offset] == tag
        else { throw PlatformFailure.custodyRewrapUnavailable }
        let length = Int(data[offset + 1]) << 8 | Int(data[offset + 2])
        let valueStart = offset + 3
        let valueEnd = valueStart + length
        guard range.contains(length), valueEnd <= data.count else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        offset = valueEnd
        return data.subdata(in: valueStart ..< valueEnd)
    }

    func finish() throws {
        guard offset == data.count else { throw PlatformFailure.custodyRewrapUnavailable }
    }
}

private extension FixedWidthInteger {
    var baseCampBigEndianBytes: [UInt8] {
        withUnsafeBytes(of: bigEndian, Array.init)
    }
}
