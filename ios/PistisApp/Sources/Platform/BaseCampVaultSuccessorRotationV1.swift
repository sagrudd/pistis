import CryptoKit
import Foundation

enum BaseCampVaultSuccessorRotationProfileV1 {
    static let challengeSchema = Data(
        "thesaurophylax.basecamp-vault-successor-rotation.v1\0".utf8
    )
    static let purpose = BaseCampVaultMigrationProfileV1.purpose
    static let recipient = BaseCampVaultMigrationProfileV1.recipient
    static let credentialSocket = BaseCampVaultMigrationProfileV1.credentialSocket
    static let maximumChallengeBytes = 4_096
    static let maximumLifetimeSeconds: UInt64 = 600
}

struct BaseCampVaultSuccessorRotationReviewV1: Equatable, Sendable {
    let operation: String
    let siteTrustDomain: String
    let purpose: String
    let recipient: String
    let currentGeneration: String
    let successorGeneration: String
    let deviceKeyID: String
    let expiresAtUnixSeconds: UInt64
}

/// Exact purpose-separated projection of Thesaurophylax eff757e's 18-field
/// successor challenge carried inside the unchanged 13-field THESMIP1 frame.
struct BaseCampVaultSuccessorRotationPresentationV1: Equatable, Sendable {
    let correlation: Data
    let canonicalChallenge: Data
    let freshHostPublicSEC1: Data
    let siteTrustDomain: String
    let successorGeneration: String
    let deviceKeyID: String
    let expectedEd25519PublicKey: Data
    let encryptedRecordDigest: Data
    let currentRevocationGeneration: UInt64
    let delegationSerial: String
    let expiresAtUnixSeconds: UInt64
    let existingHostPublicSEC1: Data
    let existingEncryptedRecord: Data

    let currentGeneration: String
    let currentBindingDigest: Data
    let enrolledDevicePublicSEC1: Data
    let issuedAtUnixSeconds: UInt64

    var review: BaseCampVaultSuccessorRotationReviewV1 {
        BaseCampVaultSuccessorRotationReviewV1(
            operation: "Rotate Base Camp vault custody for its next start",
            siteTrustDomain: siteTrustDomain,
            purpose: BaseCampVaultSuccessorRotationProfileV1.purpose,
            recipient: BaseCampVaultSuccessorRotationProfileV1.recipient,
            currentGeneration: currentGeneration,
            successorGeneration: successorGeneration,
            deviceKeyID: deviceKeyID,
            expiresAtUnixSeconds: expiresAtUnixSeconds
        )
    }

    init(
        correlation: Data,
        canonicalChallenge: Data,
        freshHostPublicSEC1: Data,
        siteTrustDomain: String,
        successorGeneration: String,
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
        guard canonicalChallenge.count <= BaseCampVaultSuccessorRotationProfileV1
                .maximumChallengeBytes,
              Self.identifier(siteTrustDomain),
              Self.generation(successorGeneration) != nil,
              Self.identifier(deviceKeyID),
              Self.identifier(delegationSerial),
              siteTrustDomain == expectedSiteTrustDomain,
              deviceKeyID == expectedDeviceKeyID,
              currentRevocationGeneration == expectedRevocationGeneration,
              correlation.count == 16, !Self.zero(correlation),
              expectedEd25519PublicKey.count == 32, !Self.zero(expectedEd25519PublicKey),
              encryptedRecordDigest.count == 32, !Self.zero(encryptedRecordDigest),
              existingEncryptedRecord.count == 60,
              Data(SHA256.hash(data: existingEncryptedRecord)) == encryptedRecordDigest,
              Self.canonicalP256(existingHostPublicSEC1),
              Self.canonicalP256(freshHostPublicSEC1),
              existingHostPublicSEC1 != freshHostPublicSEC1
        else { throw PlatformFailure.custodyRewrapUnavailable }

        var fields = try BaseCampVaultSuccessorChallengeReaderV1(canonicalChallenge)
        let challengeSite = try fields.identifier(tag: 1)
        let currentGeneration = try fields.identifier(tag: 2)
        let currentHost = try fields.bytes(tag: 3, exact: 33)
        let currentCiphertextDigest = try fields.digest(tag: 4)
        let currentBindingDigest = try fields.digest(tag: 5)
        let challengeSuccessor = try fields.identifier(tag: 6)
        let challengeDevice = try fields.identifier(tag: 7)
        let enrolledDevicePublic = try fields.bytes(tag: 8, exact: 33)
        let payloadPublic = try fields.bytes(tag: 9, exact: 32)
        let challengeRevocation = try fields.uint64(tag: 10)
        let transaction = try fields.bytes(tag: 11, exact: 16)
        let challengeDelegation = try fields.identifier(tag: 12)
        let issuedAt = try fields.uint64(tag: 13)
        let challengeExpiry = try fields.uint64(tag: 14)
        let successorHost = try fields.bytes(tag: 15, exact: 33)
        let purpose = try fields.text(tag: 16, maximum: 128)
        let recipient = try fields.text(tag: 17, maximum: 128)
        let socket = try fields.text(tag: 18, maximum: 256)
        try fields.finish()

        let currentNumber = Self.generation(currentGeneration)
        let successorNumber = Self.generation(challengeSuccessor)
        let expectedNext = currentNumber?.addingReportingOverflow(1)
        let enrolledDeviceID = "site-root-" + Data(
            SHA256.hash(data: enrolledDevicePublic)
        ).map { String(format: "%02x", $0) }.joined()

        guard challengeSite == siteTrustDomain,
              currentHost == existingHostPublicSEC1,
              Self.canonicalP256(currentHost),
              currentCiphertextDigest == encryptedRecordDigest,
              challengeSuccessor == successorGeneration,
              currentNumber != nil, let successorNumber,
              let expectedNext, !expectedNext.overflow,
              expectedNext.partialValue == successorNumber,
              challengeDevice == deviceKeyID,
              Self.canonicalP256(enrolledDevicePublic),
              enrolledDeviceID == deviceKeyID,
              payloadPublic == expectedEd25519PublicKey,
              challengeRevocation == currentRevocationGeneration,
              transaction == correlation,
              challengeDelegation == delegationSerial,
              issuedAt <= nowUnixSeconds,
              nowUnixSeconds < challengeExpiry,
              issuedAt < challengeExpiry,
              challengeExpiry - issuedAt
                <= BaseCampVaultSuccessorRotationProfileV1.maximumLifetimeSeconds,
              challengeExpiry == expiresAtUnixSeconds,
              Self.canonicalP256(successorHost),
              successorHost == freshHostPublicSEC1,
              successorHost != currentHost,
              purpose == BaseCampVaultSuccessorRotationProfileV1.purpose,
              recipient == BaseCampVaultSuccessorRotationProfileV1.recipient,
              socket == BaseCampVaultSuccessorRotationProfileV1.credentialSocket
        else { throw PlatformFailure.custodyRewrapUnavailable }

        self.correlation = correlation
        self.canonicalChallenge = canonicalChallenge
        self.freshHostPublicSEC1 = freshHostPublicSEC1
        self.siteTrustDomain = siteTrustDomain
        self.successorGeneration = successorGeneration
        self.deviceKeyID = deviceKeyID
        self.expectedEd25519PublicKey = expectedEd25519PublicKey
        self.encryptedRecordDigest = encryptedRecordDigest
        self.currentRevocationGeneration = currentRevocationGeneration
        self.delegationSerial = delegationSerial
        self.expiresAtUnixSeconds = expiresAtUnixSeconds
        self.existingHostPublicSEC1 = existingHostPublicSEC1
        self.existingEncryptedRecord = existingEncryptedRecord
        self.currentGeneration = currentGeneration
        self.currentBindingDigest = currentBindingDigest
        enrolledDevicePublicSEC1 = enrolledDevicePublic
        issuedAtUnixSeconds = issuedAt
    }

    private static func generation(_ value: String) -> UInt64? {
        let prefix = "basecamp-vault-"
        guard value.hasPrefix(prefix), identifier(value) else { return nil }
        let suffix = String(value.dropFirst(prefix.count))
        guard !suffix.isEmpty, suffix.first != "0",
              suffix.utf8.allSatisfy({ (48 ... 57).contains($0) }),
              let number = UInt64(suffix), number > 0
        else { return nil }
        return number
    }

    private static func identifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value.utf8.allSatisfy { byte in
            (48 ... 57).contains(byte) || (65 ... 90).contains(byte)
                || (97 ... 122).contains(byte) || [45, 46, 58, 95].contains(byte)
        }
    }

    private static func canonicalP256(_ value: Data) -> Bool {
        guard value.count == 33, value.first == 2 || value.first == 3 else { return false }
        return (try? P256.KeyAgreement.PublicKey(compressedRepresentation: value)) != nil
    }

    private static func zero(_ value: Data) -> Bool { value.allSatisfy { $0 == 0 } }
}

final class SecureEnclaveBaseCampVaultSuccessorRotationProducerV1: @unchecked Sendable {
    private let signer: SecureEnclaveSigner

    init() throws {
        signer = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: "Approve Base Camp vault successor rotation"
        )
    }

    func produce(
        _ presentation: BaseCampVaultSuccessorRotationPresentationV1,
        using ceremony: FaceIDCeremonyContext
    ) throws -> IphoneMediatedCustodyRewrapSubmissionV1 {
        let publicKey = try signer.publicKey(using: ceremony).compressedSEC1
        return try BaseCampVaultSuccessorCryptographicCoreV1.produce(
            presentation,
            enrolledDevicePublicSEC1: publicKey,
            sign: { try signer.sign(message: $0, using: ceremony) },
            deriveSharedSecret: {
                try signer.deriveECDHSharedSecret(
                    peerPublicCompressedSEC1: $0, using: ceremony
                )
            }
        )
    }
}

enum BaseCampVaultSuccessorCryptographicCoreV1 {
    static func produce(
        _ value: BaseCampVaultSuccessorRotationPresentationV1,
        enrolledDevicePublicSEC1: Data,
        sign: (Data) throws -> Data,
        deriveSharedSecret: (Data) throws -> Data,
        seal: (Data, SymmetricKey, Data) throws -> Data = {
            try SecureEnclaveIphoneMediatedCustodyRewrapProducer.seal(
                $0, key: $1, aadDigest: $2
            )
        }
    ) throws -> IphoneMediatedCustodyRewrapSubmissionV1 {
        guard enrolledDevicePublicSEC1 == value.enrolledDevicePublicSEC1 else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let deviceID = "site-root-" + Data(SHA256.hash(data: enrolledDevicePublicSEC1))
            .map { String(format: "%02x", $0) }.joined()
        guard deviceID == value.deviceKeyID else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let protected = try DetachedES256Cose.protectedHeaders(kid: value.deviceKeyID)
        let structure = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: value.canonicalChallenge
        )
        let cose = try DetachedES256Cose.envelope(
            protected: protected, signature: sign(structure)
        )

        var oldShared = try deriveSharedSecret(value.existingHostPublicSEC1)
        defer { zeroize(&oldShared) }
        let oldAAD = BaseCampVaultMigrationCryptographicCoreV1.purposeAAD(
            siteTrustDomain: value.siteTrustDomain,
            keyGeneration: value.currentGeneration,
            deviceKeyID: value.deviceKeyID,
            hostPublicSEC1: value.existingHostPublicSEC1
        )
        let oldKey = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
            sharedSecret: oldShared, aadDigest: oldAAD
        )
        var secret = try SecureEnclaveIphoneMediatedCustodyRewrapProducer.open(
            value.existingEncryptedRecord, key: oldKey, aadDigest: oldAAD
        )
        defer { zeroize(&secret) }
        guard secret.count == 32,
              let integrity = try? Curve25519.Signing.PrivateKey(rawRepresentation: secret),
              integrity.publicKey.rawRepresentation == value.expectedEd25519PublicKey
        else { throw PlatformFailure.custodyRewrapUnavailable }

        var freshShared = try deriveSharedSecret(value.freshHostPublicSEC1)
        defer { zeroize(&freshShared) }
        let freshAAD = BaseCampVaultMigrationCryptographicCoreV1.purposeAAD(
            siteTrustDomain: value.siteTrustDomain,
            keyGeneration: value.successorGeneration,
            deviceKeyID: value.deviceKeyID,
            hostPublicSEC1: value.freshHostPublicSEC1
        )
        let freshKey = SecureEnclaveIphoneMediatedCustodyRewrapProducer.portableWrapKey(
            sharedSecret: freshShared, aadDigest: freshAAD
        )
        let ciphertext = try seal(secret, freshKey, freshAAD)
        guard ciphertext.count == 60 else { throw PlatformFailure.custodyRewrapUnavailable }
        return IphoneMediatedCustodyRewrapSubmissionV1(
            correlation: value.correlation,
            canonicalPayload: value.canonicalChallenge,
            deviceKeyID: value.deviceKeyID,
            delegationSerial: value.delegationSerial,
            siteTrustDomain: value.siteTrustDomain,
            purpose: BaseCampVaultSuccessorRotationProfileV1.purpose,
            coseSign1: cose,
            rewrappedCiphertext: ciphertext
        )
    }

    private static func zeroize(_ value: inout Data) {
        guard !value.isEmpty else { return }
        value.resetBytes(in: value.startIndex ..< value.endIndex)
    }
}

private struct BaseCampVaultSuccessorChallengeReaderV1 {
    private let data: Data
    private var offset: Int

    init(_ data: Data) throws {
        let schema = BaseCampVaultSuccessorRotationProfileV1.challengeSchema
        guard data.count > schema.count, data.prefix(schema.count) == schema else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        self.data = data
        offset = schema.count
    }

    mutating func identifier(tag: UInt8) throws -> String {
        let value = try text(tag: tag, maximum: 128)
        guard value.utf8.allSatisfy({ byte in
            (48 ... 57).contains(byte) || (65 ... 90).contains(byte)
                || (97 ... 122).contains(byte) || [45, 46, 58, 95].contains(byte)
        }) else { throw PlatformFailure.custodyRewrapUnavailable }
        return value
    }

    mutating func text(tag: UInt8, maximum: Int) throws -> String {
        let value = try bytes(tag: tag, range: 1 ... maximum)
        guard let string = String(data: value, encoding: .utf8), Data(string.utf8) == value else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        return string
    }

    mutating func digest(tag: UInt8) throws -> Data {
        let value = try bytes(tag: tag, exact: 32)
        guard !value.allSatisfy({ $0 == 0 }) else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        return value
    }

    mutating func uint64(tag: UInt8) throws -> UInt64 {
        try bytes(tag: tag, exact: 8).reduce(0) { ($0 << 8) | UInt64($1) }
    }

    mutating func bytes(tag: UInt8, exact: Int) throws -> Data {
        try bytes(tag: tag, range: exact ... exact)
    }

    mutating func bytes(tag: UInt8, range: ClosedRange<Int>) throws -> Data {
        guard offset + 3 <= data.count, data[offset] == tag else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let length = Int(data[offset + 1]) << 8 | Int(data[offset + 2])
        let start = offset + 3
        let end = start + length
        guard range.contains(length), end <= data.count else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        offset = end
        return data.subdata(in: start ..< end)
    }

    func finish() throws {
        guard offset == data.count else { throw PlatformFailure.custodyRewrapUnavailable }
    }
}
