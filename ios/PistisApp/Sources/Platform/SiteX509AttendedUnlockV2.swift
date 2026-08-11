import CryptoKit
import Foundation

/// The two Site X.509 providers are intentionally separate protocol domains.
/// A role fixes its route, purpose, challenge role byte and generation prefix;
/// no presentation can select or redirect any of them.
enum SiteX509AttendedUnlockRoleV2: String, CaseIterable, Sendable {
    case root
    case issuer

    static let presentationSchema = "monas.site-x509-attended-unlock-presentation.v2"
    static let submissionSchema = "monas.site-x509-attended-unlock-submission.v2"
    static let acceptedSchema = "monas.site-x509-attended-unlock-accepted.v2"

    var purpose: String {
        switch self {
        case .root: "thesaurophylax.site-x509-root-rewrap.v1"
        case .issuer: "thesaurophylax.site-x509-issuer-rewrap.v1"
        }
    }

    var presentationPath: String {
        "/v1/pistis/site-x509/\(rawValue)-unlock/presentation"
    }

    var submissionPath: String {
        "/v1/pistis/site-x509/\(rawValue)-unlock/submit"
    }

    var generationPrefix: String {
        switch self {
        case .root: "x509-root-"
        case .issuer: "x509-issuing-"
        }
    }

    var challengeCode: UInt8 { self == .root ? 1 : 2 }
}

/// Strict public/ciphertext response from one fixed Monas role endpoint.
/// It is deliberately not generally Codable and verifies the complete
/// THESXIR2 canonical challenge before any Face ID operation occurs.
struct SiteX509AttendedUnlockPresentationV2: Sendable {
    static let maximumLifetimeSeconds: UInt64 = 300
    private static let challengeSchema = Data(
        "thesaurophylax.site-x509-iphone-rewrap.v2\0".utf8
    )

    let role: SiteX509AttendedUnlockRoleV2
    let purpose: String
    let correlation: Data
    let canonicalChallenge: Data
    let freshHostPublicSEC1: Data
    let siteTrustDomain: String
    let keyGeneration: String
    let deviceKeyID: String
    let expectedP256PublicSEC1: Data
    let encryptedRecordDigest: Data
    let currentRevocationGeneration: UInt64
    let delegationSerial: String
    let expiresAtUnixSeconds: UInt64
    let existingHostPublicSEC1: Data
    let existingEncryptedRecord: Data

    init(
        data: Data,
        expectedRole: SiteX509AttendedUnlockRoleV2,
        nowUnixSeconds: UInt64
    ) throws {
        let wire: Wire
        do { wire = try JSONDecoder().decode(Wire.self, from: data) }
        catch { throw PlatformFailure.custodyRewrapUnavailable }
        guard wire.schema == SiteX509AttendedUnlockRoleV2.presentationSchema,
              wire.role == expectedRole.rawValue,
              wire.purpose == expectedRole.purpose,
              wire.submissionPath == expectedRole.submissionPath,
              wire.keyGeneration.hasPrefix(expectedRole.generationPrefix),
              Self.identifier(wire.siteTrustDomain),
              Self.identifier(wire.keyGeneration),
              Self.identifier(wire.deviceKeyID),
              Self.identifier(wire.delegationSerial),
              wire.expiresAtUnixSeconds > nowUnixSeconds,
              wire.expiresAtUnixSeconds - nowUnixSeconds <= Self.maximumLifetimeSeconds,
              let correlation = Self.base64URL(wire.correlationB64URL, exact: 16),
              !correlation.allSatisfy({ $0 == 0 }),
              let challenge = Self.base64URL(wire.canonicalChallengeB64URL, range: 1 ... 4_096),
              let freshHost = Self.base64URL(wire.freshHostPublicSEC1B64URL, exact: 33),
              Self.p256Point(freshHost),
              let expectedPublic = Self.base64URL(wire.expectedP256PublicSEC1B64URL, exact: 33),
              Self.p256SigningPoint(expectedPublic),
              let digest = Self.base64URL(wire.encryptedRecordDigestB64URL, exact: 32),
              !digest.allSatisfy({ $0 == 0 }),
              let existingHost = Self.base64URL(wire.existingHostPublicSEC1B64URL, exact: 33),
              Self.p256Point(existingHost), existingHost != freshHost,
              let record = Self.base64URL(wire.existingEncryptedRecordB64URL, range: 28 ... 4_096),
              Data(SHA256.hash(data: record)) == digest
        else { throw PlatformFailure.custodyRewrapUnavailable }

        role = expectedRole
        purpose = wire.purpose
        self.correlation = correlation
        canonicalChallenge = challenge
        freshHostPublicSEC1 = freshHost
        siteTrustDomain = wire.siteTrustDomain
        keyGeneration = wire.keyGeneration
        deviceKeyID = wire.deviceKeyID
        expectedP256PublicSEC1 = expectedPublic
        encryptedRecordDigest = digest
        currentRevocationGeneration = wire.currentRevocationGeneration
        delegationSerial = wire.delegationSerial
        expiresAtUnixSeconds = wire.expiresAtUnixSeconds
        existingHostPublicSEC1 = existingHost
        existingEncryptedRecord = record
        guard try Self.reconstructChallenge(self) == challenge else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
    }

    static func reconstructChallenge(
        _ value: SiteX509AttendedUnlockPresentationV2
    ) throws -> Data {
        var output = challengeSchema
        let revocation = value.currentRevocationGeneration.bigEndianBytes
        let expiry = value.expiresAtUnixSeconds.bigEndianBytes
        for (tag, field) in [
            (UInt8(1), Data([value.role.challengeCode])),
            (2, Data(value.siteTrustDomain.utf8)),
            (3, Data(value.keyGeneration.utf8)),
            (4, Data(value.deviceKeyID.utf8)),
            (5, value.expectedP256PublicSEC1),
            (6, value.encryptedRecordDigest),
            (7, Data(revocation)),
            (8, Data(value.delegationSerial.utf8)),
            (9, Data(expiry)),
            (10, value.freshHostPublicSEC1),
        ] {
            guard !field.isEmpty, field.count <= Int(UInt16.max) else {
                throw PlatformFailure.custodyRewrapUnavailable
            }
            output.append(tag)
            output.append(contentsOf: UInt16(field.count).bigEndianBytes)
            output.append(field)
        }
        return output
    }

    private struct Wire: Decodable {
        let schema: String
        let role: String
        let purpose: String
        let correlationB64URL: String
        let canonicalChallengeB64URL: String
        let freshHostPublicSEC1B64URL: String
        let siteTrustDomain: String
        let keyGeneration: String
        let deviceKeyID: String
        let expectedP256PublicSEC1B64URL: String
        let encryptedRecordDigestB64URL: String
        let currentRevocationGeneration: UInt64
        let delegationSerial: String
        let expiresAtUnixSeconds: UInt64
        let existingHostPublicSEC1B64URL: String
        let existingEncryptedRecordB64URL: String
        let submissionPath: String

        enum CodingKeys: String, CodingKey, CaseIterable {
            case schema, role, purpose
            case correlationB64URL = "correlation_b64url"
            case canonicalChallengeB64URL = "canonical_challenge_b64url"
            case freshHostPublicSEC1B64URL = "fresh_host_public_sec1_b64url"
            case siteTrustDomain = "site_trust_domain"
            case keyGeneration = "key_generation"
            case deviceKeyID = "device_key_id"
            case expectedP256PublicSEC1B64URL = "expected_p256_public_sec1_b64url"
            case encryptedRecordDigestB64URL = "encrypted_record_digest_b64url"
            case currentRevocationGeneration = "current_revocation_generation"
            case delegationSerial = "delegation_serial"
            case expiresAtUnixSeconds = "expires_at_unix_seconds"
            case existingHostPublicSEC1B64URL = "existing_host_public_sec1_b64url"
            case existingEncryptedRecordB64URL = "existing_encrypted_record_b64url"
            case submissionPath = "submission_path"
        }

        init(from decoder: any Decoder) throws {
            let dynamic = try decoder.container(keyedBy: SiteX509DynamicKey.self)
            guard Set(dynamic.allKeys.map(\.stringValue)) == Set(CodingKeys.allCases.map(\.rawValue))
            else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unexpected Site X.509 fields")) }
            let values = try decoder.container(keyedBy: CodingKeys.self)
            schema = try values.decode(String.self, forKey: .schema)
            role = try values.decode(String.self, forKey: .role)
            purpose = try values.decode(String.self, forKey: .purpose)
            correlationB64URL = try values.decode(String.self, forKey: .correlationB64URL)
            canonicalChallengeB64URL = try values.decode(String.self, forKey: .canonicalChallengeB64URL)
            freshHostPublicSEC1B64URL = try values.decode(String.self, forKey: .freshHostPublicSEC1B64URL)
            siteTrustDomain = try values.decode(String.self, forKey: .siteTrustDomain)
            keyGeneration = try values.decode(String.self, forKey: .keyGeneration)
            deviceKeyID = try values.decode(String.self, forKey: .deviceKeyID)
            expectedP256PublicSEC1B64URL = try values.decode(String.self, forKey: .expectedP256PublicSEC1B64URL)
            encryptedRecordDigestB64URL = try values.decode(String.self, forKey: .encryptedRecordDigestB64URL)
            currentRevocationGeneration = try values.decode(UInt64.self, forKey: .currentRevocationGeneration)
            delegationSerial = try values.decode(String.self, forKey: .delegationSerial)
            expiresAtUnixSeconds = try values.decode(UInt64.self, forKey: .expiresAtUnixSeconds)
            existingHostPublicSEC1B64URL = try values.decode(String.self, forKey: .existingHostPublicSEC1B64URL)
            existingEncryptedRecordB64URL = try values.decode(String.self, forKey: .existingEncryptedRecordB64URL)
            submissionPath = try values.decode(String.self, forKey: .submissionPath)
        }
    }

    private static func identifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                || ($0 >= 97 && $0 <= 122) || [45, 46, 58, 95].contains($0)
        }
    }

    private static func p256Point(_ value: Data) -> Bool {
        value.count == 33 && (value.first == 2 || value.first == 3)
            && (try? P256.KeyAgreement.PublicKey(compressedRepresentation: value)) != nil
    }

    private static func p256SigningPoint(_ value: Data) -> Bool {
        p256Point(value) && (try? P256.Signing.PublicKey(compressedRepresentation: value)) != nil
    }

    private static func base64URL(_ value: String, exact: Int) -> Data? {
        guard let data = base64URL(value, range: exact ... exact) else { return nil }
        return data
    }

    private static func base64URL(_ value: String, range: ClosedRange<Int>) -> Data? {
        guard !value.isEmpty, !value.contains("="), value.utf8.allSatisfy({
            ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                || ($0 >= 97 && $0 <= 122) || $0 == 45 || $0 == 95
        }) else { return nil }
        let padded = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let data = Data(base64Encoded: padded), range.contains(data.count),
              data.base64URLEncoded == value else { return nil }
        return data
    }
}

struct SiteX509AttendedUnlockSubmissionV2: Encodable, Sendable {
    let schema = SiteX509AttendedUnlockRoleV2.submissionSchema
    let role: String
    let purpose: String
    let correlationB64URL: String
    let canonicalChallengeB64URL: String
    let deviceKeyID: String
    let delegationSerial: String
    let siteTrustDomain: String
    let detachedCOSESign1B64URL: String
    let rewrappedCiphertextB64URL: String

    enum CodingKeys: String, CodingKey {
        case schema, role, purpose
        case correlationB64URL = "correlation_b64url"
        case canonicalChallengeB64URL = "canonical_challenge_b64url"
        case deviceKeyID = "device_key_id"
        case delegationSerial = "delegation_serial"
        case siteTrustDomain = "site_trust_domain"
        case detachedCOSESign1B64URL = "detached_cose_sign1_b64url"
        case rewrappedCiphertextB64URL = "rewrapped_ciphertext_b64url"
    }
}

struct SiteX509AttendedUnlockAcceptedV2: Sendable {
    let role: String
    let purpose: String

    private enum CodingKeys: String, CodingKey, CaseIterable {
        case schema, role, purpose, state
    }

    init(data: Data) throws {
        let decoded: Wire
        do { decoded = try JSONDecoder().decode(Wire.self, from: data) }
        catch { throw PlatformFailure.custodyRewrapUnavailable }
        guard decoded.schema == SiteX509AttendedUnlockRoleV2.acceptedSchema,
              decoded.state == "accepted" else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        role = decoded.role
        purpose = decoded.purpose
    }

    private struct Wire: Decodable {
        let schema: String
        let role: String
        let purpose: String
        let state: String

        init(from decoder: any Decoder) throws {
            let dynamic = try decoder.container(keyedBy: SiteX509DynamicKey.self)
            guard Set(dynamic.allKeys.map(\.stringValue))
                    == Set(CodingKeys.allCases.map(\.rawValue))
            else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unexpected Site X.509 acceptance fields")) }
            let values = try decoder.container(keyedBy: CodingKeys.self)
            schema = try values.decode(String.self, forKey: .schema)
            role = try values.decode(String.self, forKey: .role)
            purpose = try values.decode(String.self, forKey: .purpose)
            state = try values.decode(String.self, forKey: .state)
        }
    }
}

/// Dedicated P-256 scalar rewrap producer. It cannot accept an Ed25519 key,
/// generic custody purpose, caller-selected role, route, key namespace or
/// fallback. One explicitly evaluated, operation-scoped Face ID context may
/// be shared only by the immediate root-then-issuer sequence; each role still
/// produces a distinct purpose-bound proof and ciphertext.
final class SecureEnclaveSiteX509AttendedUnlockProducerV2: @unchecked Sendable {
    private static let wrapInfo = Data("mnemosyne:thesaurophylax:portable-wrap:v1".utf8)
    private let signer: SecureEnclaveSigner

    init(role: SiteX509AttendedUnlockRoleV2) throws {
        signer = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: "Unlock the Site X.509 \(role.rawValue) authority"
        )
    }

    func produce(
        _ presentation: SiteX509AttendedUnlockPresentationV2,
        using ceremony: FaceIDCeremonyContext
    ) throws -> SiteX509AttendedUnlockSubmissionV2 {
        let publicKey = try signer.publicKey(using: ceremony)
        let keyID = "site-root-" + Data(SHA256.hash(data: publicKey.compressedSEC1)).hexadecimal
        guard keyID == presentation.deviceKeyID else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let protected = try DetachedES256Cose.protectedHeaders(kid: presentation.deviceKeyID)
        let structure = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: presentation.canonicalChallenge
        )
        let signature = try signer.sign(message: structure, using: ceremony)
        let cose = try DetachedES256Cose.envelope(protected: protected, signature: signature)

        var oldShared = try signer.deriveECDHSharedSecret(
            peerPublicCompressedSEC1: presentation.existingHostPublicSEC1,
            using: ceremony
        )
        defer { oldShared.zeroize() }
        let oldAAD = Self.aad(presentation, hostPublic: presentation.existingHostPublicSEC1)
        let oldKey = Self.wrapKey(shared: oldShared, aad: oldAAD)
        var scalar = try Self.open(presentation.existingEncryptedRecord, key: oldKey, aad: oldAAD)
        defer { scalar.zeroize() }
        guard scalar.count == 32,
              let generationKey = try? P256.Signing.PrivateKey(rawRepresentation: scalar),
              generationKey.publicKey.compressedRepresentation == presentation.expectedP256PublicSEC1
        else { throw PlatformFailure.custodyRewrapUnavailable }

        var freshShared = try signer.deriveECDHSharedSecret(
            peerPublicCompressedSEC1: presentation.freshHostPublicSEC1,
            using: ceremony
        )
        defer { freshShared.zeroize() }
        let freshAAD = Self.aad(presentation, hostPublic: presentation.freshHostPublicSEC1)
        let freshKey = Self.wrapKey(shared: freshShared, aad: freshAAD)
        let ciphertext = try Self.seal(scalar, key: freshKey, aad: freshAAD)
        return SiteX509AttendedUnlockSubmissionV2(
            role: presentation.role.rawValue,
            purpose: presentation.purpose,
            correlationB64URL: presentation.correlation.base64URLEncoded,
            canonicalChallengeB64URL: presentation.canonicalChallenge.base64URLEncoded,
            deviceKeyID: presentation.deviceKeyID,
            delegationSerial: presentation.delegationSerial,
            siteTrustDomain: presentation.siteTrustDomain,
            detachedCOSESign1B64URL: cose.base64URLEncoded,
            rewrappedCiphertextB64URL: ciphertext.base64URLEncoded
        )
    }

    static func aad(
        _ presentation: SiteX509AttendedUnlockPresentationV2,
        hostPublic: Data
    ) -> Data {
        var material = Data()
        for value in [
            Data(presentation.purpose.utf8), Data(presentation.siteTrustDomain.utf8),
            Data(presentation.keyGeneration.utf8), Data(presentation.deviceKeyID.utf8),
            hostPublic,
        ] {
            material.append(contentsOf: UInt32(value.count).bigEndianBytes)
            material.append(value)
        }
        return Data(SHA256.hash(data: material))
    }

    static func wrapKey(shared: Data, aad: Data) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: shared), salt: aad,
            info: wrapInfo, outputByteCount: 32
        )
    }

    static func open(_ value: Data, key: SymmetricKey, aad: Data) throws -> Data {
        guard (28 ... 4_096).contains(value.count) else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: value), using: key, authenticating: aad)
    }

    static func seal(_ value: Data, key: SymmetricKey, aad: Data) throws -> Data {
        guard value.count == 32,
              let combined = try AES.GCM.seal(value, using: key, authenticating: aad).combined,
              combined.count == 60 else { throw PlatformFailure.custodyRewrapUnavailable }
        return combined
    }
}

private struct SiteX509DynamicKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

private extension Data {
    var base64URLEncoded: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    var hexadecimal: String { map { String(format: "%02x", $0) }.joined() }

    mutating func zeroize() {
        guard !isEmpty else { return }
        resetBytes(in: startIndex ..< endIndex)
    }
}

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] { withUnsafeBytes(of: bigEndian, Array.init) }
}
