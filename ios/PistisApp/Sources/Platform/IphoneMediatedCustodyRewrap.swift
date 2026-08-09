import CryptoKit
import Foundation

/// The only purpose Thesaurophylax accepts for a restarted portable-custody
/// generation.  It is intentionally independent of Site Root delegation and
/// App Attest registration purposes.
enum IphoneMediatedCustodyRewrapPurposeV1 {
    static let value = "thesaurophylax.iphone-mediated-custody-rewrap-unlock.v1"
}

/// Exact public material for one server-owned custody-rewrap attempt.
///
/// A reviewed fixed-peer authority obtains these values from protected current
/// state only after it has verified the retained App Attest-backed Pistis
/// session.  This model is deliberately not `Codable`: it cannot turn a QR,
/// browser parameter, cookie, local file, or user input into a custody
/// ceremony.  A future fixed service transport must decode and authenticate
/// its own separately reviewed response before constructing this value.
struct IphoneMediatedCustodyRewrapPresentationV1: Sendable {
    let siteTrustDomain: String
    let keyGeneration: String
    let deviceKeyID: String
    let expectedEd25519PublicKey: Data
    let encryptedRecordDigest: Data
    let currentRevocationGeneration: UInt64
    let delegationSerial: String
    let expiresAtUnixSeconds: UInt64
    let existingHostEphemeralPublicSEC1: Data
    let existingEncryptedRecord: Data
    let freshHostEphemeralPublicSEC1: Data

    init(
        siteTrustDomain: String,
        keyGeneration: String,
        deviceKeyID: String,
        expectedEd25519PublicKey: Data,
        encryptedRecordDigest: Data,
        currentRevocationGeneration: UInt64,
        delegationSerial: String,
        expiresAtUnixSeconds: UInt64,
        existingHostEphemeralPublicSEC1: Data,
        existingEncryptedRecord: Data,
        freshHostEphemeralPublicSEC1: Data
    ) throws {
        guard [siteTrustDomain, keyGeneration, deviceKeyID, delegationSerial].allSatisfy(
            Self.validIdentifier
        ), expectedEd25519PublicKey.count == 32,
           !expectedEd25519PublicKey.allSatisfy({ $0 == 0 }),
           encryptedRecordDigest.count == 32,
           !encryptedRecordDigest.allSatisfy({ $0 == 0 }),
           expiresAtUnixSeconds != 0,
           Self.isCompressedP256(existingHostEphemeralPublicSEC1),
           Self.isCompressedP256(freshHostEphemeralPublicSEC1),
           existingHostEphemeralPublicSEC1 != freshHostEphemeralPublicSEC1,
           existingEncryptedRecord.count >= 28,
           existingEncryptedRecord.count <= 4_096,
           Data(SHA256.hash(data: existingEncryptedRecord)) == encryptedRecordDigest
        else { throw PlatformFailure.custodyRewrapUnavailable }
        self.siteTrustDomain = siteTrustDomain
        self.keyGeneration = keyGeneration
        self.deviceKeyID = deviceKeyID
        self.expectedEd25519PublicKey = expectedEd25519PublicKey
        self.encryptedRecordDigest = encryptedRecordDigest
        self.currentRevocationGeneration = currentRevocationGeneration
        self.delegationSerial = delegationSerial
        self.expiresAtUnixSeconds = expiresAtUnixSeconds
        self.existingHostEphemeralPublicSEC1 = existingHostEphemeralPublicSEC1
        self.existingEncryptedRecord = existingEncryptedRecord
        self.freshHostEphemeralPublicSEC1 = freshHostEphemeralPublicSEC1
    }

    private static func validIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value.utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
                || (byte >= 97 && byte <= 122) || [45, 46, 58, 95].contains(byte)
        }
    }

    private static func isCompressedP256(_ value: Data) -> Bool {
        guard value.count == 33, value.first == 2 || value.first == 3 else { return false }
        return (try? P256.KeyAgreement.PublicKey(compressedRepresentation: value)) != nil
    }
}

/// One non-secret iPhone result that maps exactly to Thesaurophylax's
/// `IphoneMediatedCustodyRewrapSubmissionV1` fields.
///
/// It intentionally has no JSON encoding.  Only the future fixed,
/// peer-authenticated custody transport may define an approved wire encoding;
/// a generic HTTPS, QR, browser, token, cookie, CLI, or local fallback would
/// weaken the custody boundary.
struct IphoneMediatedCustodyRewrapSubmissionV1: Sendable {
    let canonicalPayload: Data
    let deviceKeyID: String
    let delegationSerial: String
    let siteTrustDomain: String
    let purpose: String
    let coseSign1: Data
    let rewrappedCiphertext: Data
}

/// Dedicated boundary for the future fixed authenticated custody transport.
///
/// It deliberately offers no URL-based implementation.  The current Monas
/// and Thesaurophylax trees do not define an approved endpoint or wire model,
/// so emitting a network request here would be unauthenticated architecture,
/// not progress.
protocol IphoneMediatedCustodyRewrapSubmitting: Sendable {
    func submit(_ submission: IphoneMediatedCustodyRewrapSubmissionV1) async throws
}

struct UnavailableIphoneMediatedCustodyRewrapTransport:
    IphoneMediatedCustodyRewrapSubmitting
{
    func submit(_: IphoneMediatedCustodyRewrapSubmissionV1) async throws {
        throw PlatformFailure.custodyRewrapUnavailable
    }
}

/// Produces one iPhone-mediated custody rewrap without retaining a seed.
///
/// The producer uses the already-enrolled Site Root Secure Enclave key: Face
/// ID is required first for the detached ES256 proof, then independently for
/// each ECDH operation.  It opens the existing encrypted record only in
/// transient process memory and immediately re-seals the exact 32-byte seed
/// to the fresh host public key.  It neither stores, logs, returns, nor
/// projects the seed into SwiftUI state.
final class SecureEnclaveIphoneMediatedCustodyRewrapProducer: @unchecked Sendable {
    private static let challengeSchema = Data(
        "thesaurophylax.iphone-mediated-custody-rewrap.v1\0".utf8
    )
    private static let wrapHKDFInfo = Data(
        "mnemosyne:thesaurophylax:portable-wrap:v1".utf8
    )
    private let signer: SecureEnclaveSigner

    init(authenticationReason: String) throws {
        signer = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: authenticationReason
        )
    }

    /// Creates a proof and a fresh ciphertext for one exact presentation.
    ///
    /// No result exists until Face ID protected signing and both Secure
    /// Enclave ECDH operations succeed.  Any failure is coarse and produces
    /// no synthetic response.
    func produce(
        presentation: IphoneMediatedCustodyRewrapPresentationV1
    ) throws -> IphoneMediatedCustodyRewrapSubmissionV1 {
        let registration = try deviceRegistration()
        guard registration.deviceKeyID == presentation.deviceKeyID else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let canonicalPayload = try Self.canonicalChallenge(for: presentation)
        let protected = try DetachedES256Cose.protectedHeaders(kid: presentation.deviceKeyID)
        let signatureStructure = try DetachedES256Cose.signatureStructure(
            protected: protected,
            payload: canonicalPayload
        )
        let signature = try signer.sign(message: signatureStructure)
        let coseSign1 = try DetachedES256Cose.envelope(protected: protected, signature: signature)

        var oldShared = try signer.deriveECDHSharedSecret(
            peerPublicCompressedSEC1: presentation.existingHostEphemeralPublicSEC1
        )
        defer { Self.zeroize(&oldShared) }
        let oldAAD = Self.portableWrapAADDigest(
            siteTrustDomain: presentation.siteTrustDomain,
            keyGeneration: presentation.keyGeneration,
            deviceKeyID: presentation.deviceKeyID,
            hostEphemeralPublicSEC1: presentation.existingHostEphemeralPublicSEC1
        )
        let oldKey = Self.portableWrapKey(sharedSecret: oldShared, aadDigest: oldAAD)
        var seed = try Self.open(
            presentation.existingEncryptedRecord,
            key: oldKey,
            aadDigest: oldAAD
        )
        defer { Self.zeroize(&seed) }
        guard seed.count == 32 else { throw PlatformFailure.custodyRewrapUnavailable }

        var freshShared = try signer.deriveECDHSharedSecret(
            peerPublicCompressedSEC1: presentation.freshHostEphemeralPublicSEC1
        )
        defer { Self.zeroize(&freshShared) }
        let freshAAD = Self.portableWrapAADDigest(
            siteTrustDomain: presentation.siteTrustDomain,
            keyGeneration: presentation.keyGeneration,
            deviceKeyID: presentation.deviceKeyID,
            hostEphemeralPublicSEC1: presentation.freshHostEphemeralPublicSEC1
        )
        let freshKey = Self.portableWrapKey(sharedSecret: freshShared, aadDigest: freshAAD)
        let ciphertext = try Self.seal(seed, key: freshKey, aadDigest: freshAAD)
        guard ciphertext.count <= 4_096 else { throw PlatformFailure.custodyRewrapUnavailable }
        return IphoneMediatedCustodyRewrapSubmissionV1(
            canonicalPayload: canonicalPayload,
            deviceKeyID: presentation.deviceKeyID,
            delegationSerial: presentation.delegationSerial,
            siteTrustDomain: presentation.siteTrustDomain,
            purpose: IphoneMediatedCustodyRewrapPurposeV1.value,
            coseSign1: coseSign1,
            rewrappedCiphertext: ciphertext
        )
    }

    private func deviceRegistration() throws -> SiteRootKeyRegistrationV1 {
        let publicKey = try signer.create()
        let digest = SHA256.hash(data: publicKey.compressedSEC1)
        return SiteRootKeyRegistrationV1(
            schema: SiteRootKeyRegistrationV1.schema,
            deviceKeyID: "site-root-" + Self.hexadecimal(Data(digest)),
            publicKeyCompressedSEC1: publicKey.compressedSEC1,
            secureEnclaveAttestation: "not-asserted"
        )
    }

    static func canonicalChallenge(
        for presentation: IphoneMediatedCustodyRewrapPresentationV1
    ) throws -> Data {
        var result = challengeSchema
        try append(tag: 1, value: Data(presentation.siteTrustDomain.utf8), to: &result)
        try append(tag: 2, value: Data(presentation.keyGeneration.utf8), to: &result)
        try append(tag: 3, value: Data(presentation.deviceKeyID.utf8), to: &result)
        try append(tag: 4, value: presentation.expectedEd25519PublicKey, to: &result)
        try append(tag: 5, value: presentation.encryptedRecordDigest, to: &result)
        try append(
            tag: 6,
            value: withUnsafeBytes(of: presentation.currentRevocationGeneration.bigEndian) { Data($0) },
            to: &result
        )
        try append(tag: 7, value: Data(presentation.delegationSerial.utf8), to: &result)
        try append(
            tag: 8,
            value: withUnsafeBytes(of: presentation.expiresAtUnixSeconds.bigEndian) { Data($0) },
            to: &result
        )
        try append(tag: 9, value: presentation.freshHostEphemeralPublicSEC1, to: &result)
        return result
    }

    static func portableWrapAADDigest(
        siteTrustDomain: String,
        keyGeneration: String,
        deviceKeyID: String,
        hostEphemeralPublicSEC1: Data
    ) -> Data {
        var input = Data()
        for value in [
            Data(siteTrustDomain.utf8), Data(keyGeneration.utf8), Data(deviceKeyID.utf8),
            hostEphemeralPublicSEC1,
        ] {
            input.append(contentsOf: UInt32(value.count).bigEndianBytes)
            input.append(value)
        }
        return Data(SHA256.hash(data: input))
    }

    static func portableWrapKey(sharedSecret: Data, aadDigest: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: aadDigest,
            info: wrapHKDFInfo,
            outputByteCount: 32
        )
    }

    static func seal(_ plaintext: Data, key: SymmetricKey, aadDigest: Data) throws -> Data {
        guard plaintext.count == 32 else { throw PlatformFailure.custodyRewrapUnavailable }
        let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: aadDigest)
        guard let combined = sealed.combined, combined.count == 60 else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        return combined
    }

    static func open(_ record: Data, key: SymmetricKey, aadDigest: Data) throws -> Data {
        guard record.count >= 28 && record.count <= 4_096 else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let sealed = try AES.GCM.SealedBox(combined: record)
        return try AES.GCM.open(sealed, using: key, authenticating: aadDigest)
    }

    private static func append(tag: UInt8, value: Data, to output: inout Data) throws {
        guard !value.isEmpty, value.count <= Int(UInt16.max) else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        output.append(tag)
        output.append(contentsOf: UInt16(value.count).bigEndianBytes)
        output.append(value)
    }

    private static func zeroize(_ value: inout Data) {
        guard !value.isEmpty else { return }
        value.resetBytes(in: value.startIndex ..< value.endIndex)
    }

    private static func hexadecimal(_ value: Data) -> String {
        value.map { String(format: "%02x", $0) }.joined()
    }
}

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] {
        withUnsafeBytes(of: bigEndian, Array.init)
    }
}
