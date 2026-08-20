import CryptoKit
import Foundation
import Security

enum FirstAuthorityCustodyPurposeV2 {
    static let rotation = "thesaurophylax.pistis-first-device-authority-rotation.v2"
    static let recovery = "thesaurophylax.pistis-first-device-authority-recovery.v2"
}

enum FirstAuthorityCustodyModeV2: Equatable, Hashable, Sendable {
    case rotation
    case recovery
}

struct FirstAuthorityCustodyIdentityV2: Sendable {
    let siteTrustDomain: String
    let custodyGeneration: String
    let deviceKeyID: String
    let enrolledDevicePublicSEC1: Data
    let recoverySeedEd25519PublicKey: Data
    let revocationGeneration: UInt64

    init(
        siteTrustDomain: String,
        custodyGeneration: String,
        deviceKeyID: String,
        enrolledDevicePublicSEC1: Data,
        recoverySeedEd25519PublicKey: Data,
        revocationGeneration: UInt64
    ) throws {
        guard [siteTrustDomain, custodyGeneration, deviceKeyID].allSatisfy(Self.identifier),
              Self.compressedP256(enrolledDevicePublicSEC1),
              recoverySeedEd25519PublicKey.count == 32,
              !recoverySeedEd25519PublicKey.allSatisfy({ $0 == 0 }),
              revocationGeneration != 0
        else { throw PlatformFailure.custodyRewrapUnavailable }
        self.siteTrustDomain = siteTrustDomain
        self.custodyGeneration = custodyGeneration
        self.deviceKeyID = deviceKeyID
        self.enrolledDevicePublicSEC1 = enrolledDevicePublicSEC1
        self.recoverySeedEd25519PublicKey = recoverySeedEd25519PublicKey
        self.revocationGeneration = revocationGeneration
    }

    static func identifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 255 && value.utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
                || (byte >= 97 && byte <= 122) || [45, 46, 58, 95].contains(byte)
        }
    }

    static func compressedP256(_ value: Data) -> Bool {
        value.count == 33 && (value.first == 2 || value.first == 3)
            && (try? P256.KeyAgreement.PublicKey(compressedRepresentation: value)) != nil
    }
}

struct FirstAuthorityRotationPresentationV2: Sendable {
    let correlation: Data
    let identity: FirstAuthorityCustodyIdentityV2
    let hostEphemeralPublicSEC1: Data
    let legacyRecordSHA256: Data
    let installationBindingSHA256: Data
    let appAttestAcceptanceSHA256: Data
    let siteRootProofSHA256: Data
    let delegationSerial: String
    let expiresAtUnixSeconds: UInt64

    func canonicalTranscript() throws -> Data {
        try FirstAuthorityCustodyTranscriptV2.encode(
            purpose: FirstAuthorityCustodyPurposeV2.rotation,
            correlation: correlation,
            identity: identity,
            host: hostEphemeralPublicSEC1,
            digests: [legacyRecordSHA256, installationBindingSHA256,
                      appAttestAcceptanceSHA256, siteRootProofSHA256],
            delegationSerial: delegationSerial,
            expiresAtUnixSeconds: expiresAtUnixSeconds
        )
    }
}

struct FirstAuthorityRecoveryPresentationV2: Sendable {
    let correlation: Data
    let identity: FirstAuthorityCustodyIdentityV2
    let hostEphemeralPublicSEC1: Data
    let encryptedRecordSHA256: Data
    let authorityContextSHA256: Data
    let encryptedRecord: Data
    let delegationSerial: String
    let expiresAtUnixSeconds: UInt64

    func canonicalTranscript() throws -> Data {
        var result = try FirstAuthorityCustodyTranscriptV2.encode(
            purpose: FirstAuthorityCustodyPurposeV2.recovery,
            correlation: correlation,
            identity: identity,
            host: hostEphemeralPublicSEC1,
            digests: [encryptedRecordSHA256, authorityContextSHA256],
            delegationSerial: delegationSerial,
            expiresAtUnixSeconds: expiresAtUnixSeconds
        )
        try FirstAuthorityCustodyTranscriptV2.append(encryptedRecord, to: &result)
        return result
    }
}

enum FirstAuthorityCustodyTranscriptV2 {
    static func encode(
        purpose: String,
        correlation: Data,
        identity: FirstAuthorityCustodyIdentityV2,
        host: Data,
        digests: [Data],
        delegationSerial: String,
        expiresAtUnixSeconds: UInt64
    ) throws -> Data {
        guard correlation.count == 16, !correlation.allSatisfy({ $0 == 0 }),
              FirstAuthorityCustodyIdentityV2.compressedP256(host),
              digests.allSatisfy({ $0.count == 32 && !$0.allSatisfy({ $0 == 0 }) }),
              FirstAuthorityCustodyIdentityV2.identifier(delegationSerial),
              expiresAtUnixSeconds != 0
        else { throw PlatformFailure.custodyRewrapUnavailable }
        var result = Data()
        let expires = withUnsafeBytes(of: expiresAtUnixSeconds.bigEndian) { Data($0) }
        let revocation = withUnsafeBytes(of: identity.revocationGeneration.bigEndian) { Data($0) }
        for field in [Data(purpose.utf8), correlation, Data(identity.siteTrustDomain.utf8),
                      Data(identity.custodyGeneration.utf8), Data(identity.deviceKeyID.utf8),
                      identity.enrolledDevicePublicSEC1,
                      identity.recoverySeedEd25519PublicKey, revocation, host] + digests
            + [Data(delegationSerial.utf8), expires] {
            try append(field, to: &result)
        }
        return result
    }

    static func append(_ field: Data, to output: inout Data) throws {
        guard !field.isEmpty, let length = UInt32(exactly: field.count) else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        output.append(contentsOf: withUnsafeBytes(of: length.bigEndian, Array.init))
        output.append(field)
    }
}

struct FirstAuthorityCustodySubmissionV2: Sendable {
    let correlation: Data
    let detachedCOSESign1: Data
    let rewrappedSeedCiphertext: Data
}

struct FirstAuthorityCustodyAcceptedV2: Sendable {
    let correlation: Data
    let authorityDescriptor: Data

    init(correlation: Data, authorityDescriptor: Data) throws {
        guard correlation.count == 16, !correlation.allSatisfy({ $0 == 0 }),
              !authorityDescriptor.isEmpty, authorityDescriptor.count <= 16_384
        else { throw PlatformFailure.custodyRewrapUnavailable }
        self.correlation = correlation
        self.authorityDescriptor = authorityDescriptor
    }
}

struct FirstAuthorityCustodySeedCommitmentV2: Sendable {
    let deviceKeyID: String
    let enrolledDevicePublicSEC1: Data
    let recoverySeedEd25519PublicKey: Data
}

protocol FirstAuthorityRecoveryEnvelopeStoring: Sendable {
    func load() throws -> Data?
    func insert(_ envelope: Data) throws
}

final class KeychainFirstAuthorityRecoveryEnvelopeStore:
    FirstAuthorityRecoveryEnvelopeStoring, @unchecked Sendable
{
    private let service = "org.mnemosyne.pistis.first-authority-recovery-envelope.v2"

    func load() throws -> Data? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        return data
    }

    func insert(_ envelope: Data) throws {
        guard !envelope.isEmpty, try load() == nil else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        var value = baseQuery()
        value[kSecValueData as String] = envelope
        value[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(value as CFDictionary, nil) == errSecSuccess else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
    }

    private func baseQuery() -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: "site-root-v2"]
    }
}

private struct FirstAuthorityRecoverySeedEnvelopeV2: Codable {
    static let schema = "pistis.first-authority-recovery-seed-envelope.v2"
    let schema: String
    let deviceKeyID: String
    let recoveryPublicKeyB64URL: String
    let localEphemeralPublicSEC1B64URL: String
    let ciphertextB64URL: String
}

final class SecureEnclaveFirstAuthorityCustodyProducerV2: @unchecked Sendable {
    private static let localEnvelopeInfo = Data("pistis:first-authority-recovery-envelope:v2".utf8)
    /// The accepted portable ECDH key-wrap profile shared with Thesaurophylax.
    /// This must remain byte-for-byte identical to PORTABLE_ECDH_KEY_WRAP_V1.
    static let hostEnvelopeInfo = Data(
        "mnemosyne:thesaurophylax:portable-wrap:v1".utf8
    )
    private let signer: SecureEnclaveSigner
    private let store: any FirstAuthorityRecoveryEnvelopeStoring

    init(
        authenticationReason: String,
        store: any FirstAuthorityRecoveryEnvelopeStoring = KeychainFirstAuthorityRecoveryEnvelopeStore()
    ) throws {
        signer = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1", authenticationReason: authenticationReason
        )
        self.store = store
    }

    func prepareInitialRotation() throws -> FirstAuthorityCustodySeedCommitmentV2 {
        let device = try signer.create()
        let deviceKeyID = Self.deviceKeyID(device.compressedSEC1)
        if let existing = try store.load() {
            let envelope = try decodeEnvelope(existing)
            guard envelope.deviceKeyID == deviceKeyID,
                  let commitment = Self.decode(envelope.recoveryPublicKeyB64URL)
            else { throw PlatformFailure.custodyRewrapUnavailable }
            return FirstAuthorityCustodySeedCommitmentV2(
                deviceKeyID: deviceKeyID,
                enrolledDevicePublicSEC1: device.compressedSEC1,
                recoverySeedEd25519PublicKey: commitment
            )
        }
        var seed = Data(count: 32)
        guard seed.withUnsafeMutableBytes({ bytes in
            SecRandomCopyBytes(kSecRandomDefault, 32, bytes.baseAddress!)
        }) == errSecSuccess, !seed.allSatisfy({ $0 == 0 }) else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        defer { seed.resetBytes(in: seed.startIndex ..< seed.endIndex) }
        let commitment = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            .publicKey.rawRepresentation
        let localPrivate = P256.KeyAgreement.PrivateKey()
        let securePublic = try P256.KeyAgreement.PublicKey(
            compressedRepresentation: device.compressedSEC1
        )
        let shared = try localPrivate.sharedSecretFromKeyAgreement(with: securePublic)
        let localPublic = localPrivate.publicKey.compressedRepresentation
        let aad = Self.localAAD(deviceKeyID: deviceKeyID, commitment: commitment,
                                localPublic: localPublic)
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: aad, sharedInfo: Self.localEnvelopeInfo,
            outputByteCount: 32
        )
        let ciphertext = try Self.seal(seed, key: key, aad: aad)
        let envelope = FirstAuthorityRecoverySeedEnvelopeV2(
            schema: FirstAuthorityRecoverySeedEnvelopeV2.schema,
            deviceKeyID: deviceKeyID,
            recoveryPublicKeyB64URL: Self.base64URL(commitment),
            localEphemeralPublicSEC1B64URL: Self.base64URL(localPublic),
            ciphertextB64URL: Self.base64URL(ciphertext)
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try store.insert(try encoder.encode(envelope))
        return FirstAuthorityCustodySeedCommitmentV2(
            deviceKeyID: deviceKeyID, enrolledDevicePublicSEC1: device.compressedSEC1,
            recoverySeedEd25519PublicKey: commitment
        )
    }

    func retainedRecoveryCommitment() throws -> FirstAuthorityCustodySeedCommitmentV2 {
        let device = try signer.publicKey()
        let deviceKeyID = Self.deviceKeyID(device.compressedSEC1)
        guard let data = try store.load() else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let envelope = try decodeEnvelope(data)
        guard envelope.deviceKeyID == deviceKeyID,
              let commitment = Self.decode(envelope.recoveryPublicKeyB64URL)
        else { throw PlatformFailure.custodyRewrapUnavailable }
        return FirstAuthorityCustodySeedCommitmentV2(
            deviceKeyID: deviceKeyID, enrolledDevicePublicSEC1: device.compressedSEC1,
            recoverySeedEd25519PublicKey: commitment
        )
    }

    func completeInitialRotation(
        _ presentation: FirstAuthorityRotationPresentationV2
    ) throws -> FirstAuthorityCustodySubmissionV2 {
        try complete(correlation: presentation.correlation, identity: presentation.identity,
                     host: presentation.hostEphemeralPublicSEC1,
                     transcript: presentation.canonicalTranscript())
    }

    func completeRecovery(
        _ presentation: FirstAuthorityRecoveryPresentationV2
    ) throws -> FirstAuthorityCustodySubmissionV2 {
        guard Data(SHA256.hash(data: presentation.encryptedRecord))
                == presentation.encryptedRecordSHA256 else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        return try complete(correlation: presentation.correlation, identity: presentation.identity,
                            host: presentation.hostEphemeralPublicSEC1,
                            transcript: presentation.canonicalTranscript())
    }

    private func complete(
        correlation: Data, identity: FirstAuthorityCustodyIdentityV2,
        host: Data, transcript: Data
    ) throws -> FirstAuthorityCustodySubmissionV2 {
        let envelope = try loadEnvelope(identity: identity)
        var seed = try openLocalSeed(envelope)
        defer { seed.resetBytes(in: seed.startIndex ..< seed.endIndex) }
        guard try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            .publicKey.rawRepresentation == identity.recoverySeedEd25519PublicKey else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let protected = try DetachedES256Cose.protectedHeaders(kid: identity.deviceKeyID)
        let structure = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: transcript
        )
        let signature = try signer.sign(message: structure)
        let cose = try DetachedES256Cose.envelope(protected: protected, signature: signature)
        var shared = try signer.deriveECDHSharedSecret(peerPublicCompressedSEC1: host)
        defer { shared.resetBytes(in: shared.startIndex ..< shared.endIndex) }
        let aad = Data(SHA256.hash(data: transcript))
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: shared), salt: aad,
            info: Self.hostEnvelopeInfo, outputByteCount: 32
        )
        return FirstAuthorityCustodySubmissionV2(
            correlation: correlation, detachedCOSESign1: cose,
            rewrappedSeedCiphertext: try Self.seal(seed, key: key, aad: aad)
        )
    }

    private func loadEnvelope(
        identity: FirstAuthorityCustodyIdentityV2
    ) throws -> FirstAuthorityRecoverySeedEnvelopeV2 {
        guard let data = try store.load() else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let value = try decodeEnvelope(data)
        guard
              value.deviceKeyID == identity.deviceKeyID,
              Self.decode(value.recoveryPublicKeyB64URL) == identity.recoverySeedEd25519PublicKey
        else { throw PlatformFailure.custodyRewrapUnavailable }
        return value
    }

    private func decodeEnvelope(_ data: Data) throws -> FirstAuthorityRecoverySeedEnvelopeV2 {
        guard data.count <= 4_096,
              let value = try? JSONDecoder().decode(
                  FirstAuthorityRecoverySeedEnvelopeV2.self, from: data
              ),
              value.schema == FirstAuthorityRecoverySeedEnvelopeV2.schema,
              let commitment = Self.decode(value.recoveryPublicKeyB64URL),
              commitment.count == 32,
              let localPublic = Self.decode(value.localEphemeralPublicSEC1B64URL),
              FirstAuthorityCustodyIdentityV2.compressedP256(localPublic),
              let ciphertext = Self.decode(value.ciphertextB64URL), ciphertext.count == 60
        else { throw PlatformFailure.custodyRewrapUnavailable }
        return value
    }

    private func openLocalSeed(_ envelope: FirstAuthorityRecoverySeedEnvelopeV2) throws -> Data {
        guard let localPublic = Self.decode(envelope.localEphemeralPublicSEC1B64URL),
              let ciphertext = Self.decode(envelope.ciphertextB64URL) else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        var shared = try signer.deriveECDHSharedSecret(peerPublicCompressedSEC1: localPublic)
        defer { shared.resetBytes(in: shared.startIndex ..< shared.endIndex) }
        guard let commitment = Self.decode(envelope.recoveryPublicKeyB64URL) else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let aad = Self.localAAD(deviceKeyID: envelope.deviceKeyID, commitment: commitment,
                                localPublic: localPublic)
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: shared), salt: aad,
            info: Self.localEnvelopeInfo, outputByteCount: 32
        )
        let seed = try Self.open(ciphertext, key: key, aad: aad)
        guard seed.count == 32 else { throw PlatformFailure.custodyRewrapUnavailable }
        return seed
    }

    private static func localAAD(deviceKeyID: String, commitment: Data,
                                 localPublic: Data) -> Data {
        var value = Data(localEnvelopeInfo)
        for field in [Data(deviceKeyID.utf8), commitment, localPublic] {
            value.append(contentsOf: withUnsafeBytes(of: UInt32(field.count).bigEndian, Array.init))
            value.append(field)
        }
        return Data(SHA256.hash(data: value))
    }

    static func seal(_ seed: Data, key: SymmetricKey, aad: Data) throws -> Data {
        guard seed.count == 32 else { throw PlatformFailure.custodyRewrapUnavailable }
        let box = try AES.GCM.seal(seed, using: key, authenticating: aad)
        guard let combined = box.combined, combined.count == 60 else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        return combined
    }

    static func open(_ ciphertext: Data, key: SymmetricKey, aad: Data) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: ciphertext), using: key,
                         authenticating: aad)
    }

    private static func deviceKeyID(_ publicKey: Data) -> String {
        "site-root-" + SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined()
    }

    private static func base64URL(_ value: Data) -> String {
        value.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private static func decode(_ value: String) -> Data? {
        guard !value.isEmpty, !value.contains("=") else { return nil }
        let padded = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let data = Data(base64Encoded: padded), base64URL(data) == value else { return nil }
        return data
    }
}
