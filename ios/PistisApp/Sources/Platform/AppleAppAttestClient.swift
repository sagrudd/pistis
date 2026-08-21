import CryptoKit
import DeviceCheck
import Foundation
import Security

/// The reviewed, purpose-separated registration protocol between Pistis and
/// Monas. This client prepares the request only; it neither submits it nor
/// treats preparation as a successful Monas registration.
struct AppleAppAttestRegistrationEnvelope: Codable, Equatable, Sendable {
    static let protocolVersion = "pistis.apple-app-attest-registration.v1"
    static let reviewedAppIdentifier = "C7A6NQTSY4.org.mnemosynebiosciences.pistis"

    /// Exact wire discriminator required by Monas.  This is deliberately
    /// encoded as `protocol`, not `version`: the receiver rejects unknown
    /// fields before it considers Apple evidence.
    let wireProtocol: String
    let ceremonyID: String
    let siteTrustDomain: String
    let appIdentifier: String
    let keyIDB64URL: String
    let clientDataHashB64URL: String
    let attestationObjectB64URL: String

    enum CodingKeys: String, CodingKey {
        case wireProtocol = "protocol"
        case ceremonyID = "ceremony_id"
        case siteTrustDomain = "site_trust_domain"
        case appIdentifier = "app_identifier"
        case keyIDB64URL = "key_id_b64url"
        case clientDataHashB64URL = "client_data_hash_b64url"
        case attestationObjectB64URL = "attestation_object_b64url"
    }

    init(
        ceremonyID: String,
        siteTrustDomain: String,
        appleKeyID: String,
        clientDataHash: Data,
        attestationObject: Data
    ) throws {
        guard Self.validIdentifier(ceremonyID, maximumLength: 128),
            Self.validIdentifier(siteTrustDomain, maximumLength: 255),
            clientDataHash.count == 32,
            !attestationObject.isEmpty,
            attestationObject.count <= 262_144,
            let credentialID = Data(base64Encoded: appleKeyID)
        else {
            throw PlatformFailure.appAttestInvalidInput
        }

        wireProtocol = Self.protocolVersion
        self.ceremonyID = ceremonyID
        self.siteTrustDomain = siteTrustDomain
        appIdentifier = Self.reviewedAppIdentifier
        keyIDB64URL = Self.base64URL(credentialID)
        clientDataHashB64URL = Self.base64URL(clientDataHash)
        attestationObjectB64URL = Self.base64URL(attestationObject)
    }

    /// A bounded audit value that deliberately excludes the Apple credential,
    /// challenge digest, and attestation object.
    var redactedDiagnostic: String {
        "\(wireProtocol) ceremony=\(ceremonyID) site=\(siteTrustDomain) prepared"
    }

    private static func validIdentifier(_ value: String, maximumLength: Int) -> Bool {
        !value.isEmpty
            && value.utf8.count <= maximumLength
            && value.unicodeScalars.allSatisfy { scalar in
                (scalar.value >= 0x21 && scalar.value <= 0x7e)
            }
    }

    private static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// The purpose-separated assertion envelope accepted only by Monas's exact
/// Site Trust ingress. It deliberately carries neither a challenge nor a
/// session, and a successful HTTP delivery is not a completed Monas session.
struct AppleAppAttestAssertionEnvelope: Codable, Equatable, Sendable {
    static let ingressProfile =
        "mnemosyne.pistis.site-trust-app-attest-assertion-ingress.v1"

    let profile: String
    let ceremonyIDB64URL: String
    let assertionB64URL: String

    enum CodingKeys: String, CodingKey {
        case profile
        case ceremonyIDB64URL = "ceremony_id_b64url"
        case assertionB64URL = "assertion_b64url"
    }

    init(ceremonyID: Data, assertion: Data) throws {
        guard ceremonyID.count == 16,
            !ceremonyID.allSatisfy({ $0 == 0 }),
            !assertion.isEmpty,
            assertion.count <= 16_384
        else { throw PlatformFailure.appAttestInvalidInput }
        profile = Self.ingressProfile
        ceremonyIDB64URL = Self.base64URL(ceremonyID)
        assertionB64URL = Self.base64URL(assertion)
    }

    private static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// Persists only Apple's opaque key identifier. The private App Attest key is
/// managed by the operating system and is never read, exported, or logged by
/// Pistis.
protocol AppleAppAttestKeyIDStoring: Sendable {
    func loadKeyID() -> String?
    func saveKeyID(_ keyID: String) throws
}

struct PendingAppAttestReplacementKeyV1: Equatable, Sendable {
    let transactionUUID: Data
    let expectedCurrentKeyID: String
    let localPrimaryKeyID: String
    let replacementKeyID: String
    let canonicalSubmission: Data?

    init(
        transactionUUID: Data,
        expectedCurrentKeyID: String,
        localPrimaryKeyID: String,
        replacementKeyID: String,
        canonicalSubmission: Data? = nil
    ) throws {
        guard transactionUUID.count == 16,
            !transactionUUID.allSatisfy({ $0 == 0 }),
            Self.canonicalKeyID(expectedCurrentKeyID) != nil,
            Self.canonicalKeyID(localPrimaryKeyID) != nil,
            Self.canonicalKeyID(replacementKeyID) != nil,
            expectedCurrentKeyID != replacementKeyID,
            localPrimaryKeyID != replacementKeyID
        else { throw PlatformFailure.appAttestInvalidInput }
        if let canonicalSubmission {
            let submission = try AppAttestKeyReplacementSubmissionV1(
                canonicalBytes: canonicalSubmission
            )
            guard PXARJSON.canonicalUUID(submission.presentation.transactionID)
                    == transactionUUID,
                  submission.presentation.oldKeyIDB64URL
                    == PXARJSON.base64URL(Self.canonicalKeyID(expectedCurrentKeyID)!),
                  submission.approval.newKeyIDB64URL
                    == PXARJSON.base64URL(Self.canonicalKeyID(replacementKeyID)!)
            else { throw PlatformFailure.appAttestInvalidInput }
        }
        self.transactionUUID = transactionUUID
        self.expectedCurrentKeyID = expectedCurrentKeyID
        self.localPrimaryKeyID = localPrimaryKeyID
        self.replacementKeyID = replacementKeyID
        self.canonicalSubmission = canonicalSubmission
    }

    func retaining(canonicalSubmission: Data) throws -> Self {
        try Self(
            transactionUUID: transactionUUID,
            expectedCurrentKeyID: expectedCurrentKeyID,
            localPrimaryKeyID: localPrimaryKeyID,
            replacementKeyID: replacementKeyID,
            canonicalSubmission: canonicalSubmission
        )
    }

    static func canonicalKeyID(_ value: String) -> Data? {
        guard !value.isEmpty, value.utf8.count <= 512,
            let decoded = Data(base64Encoded: value), decoded.count == 32,
            decoded.base64EncodedString() == value
        else { return nil }
        return decoded
    }
}

protocol AppleAppAttestReplacementKeyStoring: Sendable {
    func loadPending() -> PendingAppAttestReplacementKeyV1?
    func savePending(_ value: PendingAppAttestReplacementKeyV1) throws
    func commitPending(_ value: PendingAppAttestReplacementKeyV1) throws
    func discardPending(transactionUUID: Data) throws
}

/// Narrow boundary around the Apple framework. This makes exact input hashing
/// testable without a simulator pretending to be a physical iPhone.
protocol AppleAppAttestServicing: AnyObject, Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data
}

final class DeviceCheckAppAttestService: AppleAppAttestServicing, @unchecked Sendable {
    private let service: DCAppAttestService

    init(service: DCAppAttestService = .shared) {
        self.service = service
    }

    var isSupported: Bool { service.isSupported }

    func generateKey() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            service.generateKey { keyID, error in
                if let keyID {
                    continuation.resume(returning: keyID)
                } else {
                    continuation.resume(
                        throwing: error ?? PlatformFailure.appAttestKeyCreationFailed
                    )
                }
            }
        }
    }

    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.attestKey(keyID, clientDataHash: clientDataHash) { object, error in
                if let object {
                    continuation.resume(returning: object)
                } else {
                    continuation.resume(
                        throwing: error ?? PlatformFailure.appAttestAttestationFailed
                    )
                }
            }
        }
    }

    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.generateAssertion(keyID, clientDataHash: clientDataHash) { assertion, error in
                if let assertion {
                    continuation.resume(returning: assertion)
                } else {
                    continuation.resume(
                        throwing: error ?? PlatformFailure.appAttestAssertionFailed
                    )
                }
            }
        }
    }
}

final class KeychainAppleAppAttestKeyIDStore: AppleAppAttestKeyIDStoring, @unchecked Sendable {
    private let service = "org.mnemosynebiosciences.pistis.app-attest-key-id.v1"
    private let account = "primary"

    func loadKeyID() -> String? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
            let data = result as? Data,
            let keyID = String(data: data, encoding: .utf8),
            !keyID.isEmpty,
            keyID.utf8.count <= 512
        else { return nil }
        return keyID
    }

    func saveKeyID(_ keyID: String) throws {
        guard !keyID.isEmpty, keyID.utf8.count <= 512 else {
            throw PlatformFailure.appAttestKeyCreationFailed
        }
        let data = Data(keyID.utf8)
        let query = baseQuery()
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd((query.merging(attributes) { _, new in new }) as CFDictionary, nil)
        guard
            status == errSecSuccess
                || (status == errSecDuplicateItem
                    && SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
                        == errSecSuccess)
        else { throw PlatformFailure.appAttestKeyCreationFailed }
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

final class KeychainAppleAppAttestReplacementKeyStore:
    AppleAppAttestReplacementKeyStoring, @unchecked Sendable
{
    private let pendingService = "org.mnemosynebiosciences.pistis.app-attest-replacement.v1"
    private let primary = KeychainAppleAppAttestKeyIDStore()
    private let account = "pending"
    private static let magicV1 = Data("PXAK/v1\0".utf8)
    private static let magicV2 = Data("PXAK/v2\0".utf8)

    func loadPending() -> PendingAppAttestReplacementKeyV1? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
            let bytes = result as? Data
        else { return nil }
        return try? Self.decode(bytes)
    }

    func savePending(_ value: PendingAppAttestReplacementKeyV1) throws {
        if let retained = loadPending() {
            if retained == value { return }
            guard retained.transactionUUID == value.transactionUUID,
                  retained.expectedCurrentKeyID == value.expectedCurrentKeyID,
                  retained.localPrimaryKeyID == value.localPrimaryKeyID,
                  retained.replacementKeyID == value.replacementKeyID,
                  retained.canonicalSubmission == nil,
                  value.canonicalSubmission != nil
            else { throw PlatformFailure.appAttestInvalidInput }
            let status = SecItemUpdate(
                baseQuery() as CFDictionary,
                [kSecValueData as String: Self.encode(value)] as CFDictionary
            )
            guard status == errSecSuccess else {
                throw PlatformFailure.appAttestKeyCreationFailed
            }
            return
        }
        let attributes: [String: Any] = [
            kSecValueData as String: Self.encode(value),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        guard
            SecItemAdd(
                (baseQuery().merging(attributes) { _, new in new }) as CFDictionary, nil
            ) == errSecSuccess
        else { throw PlatformFailure.appAttestKeyCreationFailed }
    }

    func commitPending(_ value: PendingAppAttestReplacementKeyV1) throws {
        guard loadPending() == value,
            let current = primary.loadKeyID(),
            current == value.localPrimaryKeyID || current == value.replacementKeyID
        else { throw PlatformFailure.appAttestInvalidInput }
        if current != value.replacementKeyID {
            try primary.saveKeyID(value.replacementKeyID)
        }
        guard SecItemDelete(baseQuery() as CFDictionary) == errSecSuccess else {
            throw PlatformFailure.appAttestKeyCreationFailed
        }
    }

    func discardPending(transactionUUID: Data) throws {
        guard let retained = loadPending() else { return }
        guard retained.transactionUUID == transactionUUID,
            primary.loadKeyID() == retained.localPrimaryKeyID
        else {
            throw PlatformFailure.appAttestInvalidInput
        }
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PlatformFailure.appAttestKeyCreationFailed
        }
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: pendingService,
            kSecAttrAccount as String: account,
        ]
    }

    static func encode(_ value: PendingAppAttestReplacementKeyV1) -> Data {
        var bytes = magicV2
        bytes.append(value.transactionUUID)
        for field in [
            value.expectedCurrentKeyID, value.localPrimaryKeyID, value.replacementKeyID,
        ] {
            let encoded = Data(field.utf8)
            bytes.append(UInt8(encoded.count >> 8))
            bytes.append(UInt8(encoded.count & 0xff))
            bytes.append(encoded)
        }
        let submission = value.canonicalSubmission ?? Data()
        let count = UInt32(submission.count)
        bytes.append(UInt8((count >> 24) & 0xff))
        bytes.append(UInt8((count >> 16) & 0xff))
        bytes.append(UInt8((count >> 8) & 0xff))
        bytes.append(UInt8(count & 0xff))
        bytes.append(submission)
        return bytes
    }

    static func decode(_ bytes: Data) throws -> PendingAppAttestReplacementKeyV1 {
        let isV2 = bytes.prefix(magicV2.count) == magicV2
        guard bytes.count >= magicV1.count + 20,
            isV2 || bytes.prefix(magicV1.count) == magicV1
        else { throw PlatformFailure.appAttestInvalidInput }
        var cursor = magicV1.count
        let transaction = bytes[cursor..<cursor + 16]
        cursor += 16
        var fields: [String] = []
        for _ in 0..<3 {
            guard cursor + 2 <= bytes.count else {
                throw PlatformFailure.appAttestInvalidInput
            }
            let count = Int(bytes[cursor]) << 8 | Int(bytes[cursor + 1])
            cursor += 2
            guard count > 0, cursor + count <= bytes.count,
                let value = String(data: bytes[cursor..<cursor + count], encoding: .utf8)
            else { throw PlatformFailure.appAttestInvalidInput }
            cursor += count
            fields.append(value)
        }
        var submission: Data?
        if isV2 {
            guard cursor + 4 <= bytes.count else {
                throw PlatformFailure.appAttestInvalidInput
            }
            let count = Int(bytes[cursor]) << 24 | Int(bytes[cursor + 1]) << 16
                | Int(bytes[cursor + 2]) << 8 | Int(bytes[cursor + 3])
            cursor += 4
            guard count <= AppAttestKeyReplacementOfflineProfileV1.maximumJSONBytes,
                  cursor + count == bytes.count
            else { throw PlatformFailure.appAttestInvalidInput }
            if count > 0 { submission = Data(bytes[cursor..<cursor + count]) }
            cursor += count
        }
        guard cursor == bytes.count else { throw PlatformFailure.appAttestInvalidInput }
        return try PendingAppAttestReplacementKeyV1(
            transactionUUID: Data(transaction), expectedCurrentKeyID: fields[0],
            localPrimaryKeyID: fields[1], replacementKeyID: fields[2],
            canonicalSubmission: submission
        )
    }
}

/// Apple App Attest adapter for one Monas registration ceremony.
///
/// The raw Monas challenge exists only for the duration of `prepareRegistration`.
/// The returned envelope must be delivered directly to the reviewed Monas
/// authority; callers must not persist, log, or place it in a QR code.
final class AppleAppAttestClient: @unchecked Sendable {
    static let assertionClientDataPrefix = Data(
        "mnemosyne.pistis.site-trust-app-attest-client-data.v1\0".utf8
    )

    private let service: AppleAppAttestServicing
    private let keyIDStore: AppleAppAttestKeyIDStoring
    private let replacementStore: AppleAppAttestReplacementKeyStoring

    init(
        service: AppleAppAttestServicing = DeviceCheckAppAttestService(),
        keyIDStore: AppleAppAttestKeyIDStoring = KeychainAppleAppAttestKeyIDStore(),
        replacementStore: AppleAppAttestReplacementKeyStoring =
            KeychainAppleAppAttestReplacementKeyStore()
    ) {
        self.service = service
        self.keyIDStore = keyIDStore
        self.replacementStore = replacementStore
    }

    /// Creates a v1 registration envelope for an exact, one-use Monas
    /// ceremony. A caller must retain the raw server challenge only in memory.
    func prepareRegistration(
        ceremonyID: String,
        siteTrustDomain: String,
        serverChallenge: Data
    ) async throws -> AppleAppAttestRegistrationEnvelope {
        let clientDataHash = Data(SHA256.hash(data: serverChallenge))
        return try await prepareRegistration(
            ceremonyID: ceremonyID,
            siteTrustDomain: siteTrustDomain,
            clientDataHash: clientDataHash
        )
    }

    /// Creates a registration envelope when the only reviewed server input is
    /// the exact, already-derived 32-byte client-data hash. This is used by
    /// the sealed Site Root bootstrap bridge; it must not derive, substitute,
    /// log, persist, or double-hash the server-held value.
    func prepareRegistration(
        ceremonyID: String,
        siteTrustDomain: String,
        clientDataHash: Data
    ) async throws -> AppleAppAttestRegistrationEnvelope {
        guard service.isSupported else { throw PlatformFailure.appAttestUnavailable }
        guard clientDataHash.count == 32, !clientDataHash.allSatisfy({ $0 == 0 }) else {
            throw PlatformFailure.appAttestInvalidInput
        }

        // Apple permits attestation only once for each App Attest key. A
        // previously retained key therefore cannot be reused for a fresh
        // registration after an interrupted ceremony. Generate a distinct
        // key for this exact registration and retain its opaque identifier
        // only after Apple has returned genuine attestation evidence; the
        // retained identifier is then used exclusively for the following
        // assertion flow.
        let keyID = try await newRegistrationKeyID()
        let attestationObject = try await attest(
            keyID: keyID,
            clientDataHash: clientDataHash
        )
        try keyIDStore.saveKeyID(keyID)
        return try AppleAppAttestRegistrationEnvelope(
            ceremonyID: ceremonyID,
            siteTrustDomain: siteTrustDomain,
            appleKeyID: keyID,
            clientDataHash: clientDataHash,
            attestationObject: attestationObject
        )
    }

    /// Uses the registered physical iPhone key to make a single assertion for
    /// the exact server-issued ceremony. The assertion and its input never
    /// leave this call except in the returned, bounded wire envelope.
    func prepareAssertion(
        bootstrap: MonasAppAttestCeremonyBootstrap
    ) async throws -> AppleAppAttestAssertionEnvelope {
        guard service.isSupported,
            let keyID = existingKeyID()
        else { throw PlatformFailure.appAttestUnavailable }

        let clientData = Self.assertionClientDataPrefix + bootstrap.challengeDigest
        let clientDataHash = Data(SHA256.hash(data: clientData))
        let assertion = try await service.generateAssertion(
            keyID,
            clientDataHash: clientDataHash
        )
        return try AppleAppAttestAssertionEnvelope(
            ceremonyID: bootstrap.ceremonyID,
            assertion: assertion
        )
    }

    /// Produces the exact fresh custody-rotation assertion supplied by Monas.
    /// The server has already purpose-separated and hashed the challenge, so
    /// this path must neither rehash nor substitute bootstrap/session material.
    func prepareCustodyRotationAssertion(
        challenge: CustodyRotationAppAttestChallengeV2
    ) async throws -> AppleAppAttestAssertionEnvelope {
        guard service.isSupported, let keyID = existingKeyID(),
            let decodedKeyID = Data(base64Encoded: keyID),
            decodedKeyID == challenge.keyID
        else { throw PlatformFailure.appAttestUnavailable }
        let assertion = try await service.generateAssertion(
            keyID, clientDataHash: challenge.clientDataHash
        )
        return try AppleAppAttestAssertionEnvelope(
            ceremonyID: challenge.ceremonyID, assertion: assertion
        )
    }

    /// Produces one fresh assertion for the exact, purpose-separated MTGS
    /// recovery challenge carried by a strictly validated Monas invitation.
    func prepareMTGSRecoveryAssertion(
        presentation: MTGSRecoveryPresentationV1
    ) async throws -> AppleAppAttestAssertionEnvelope {
        guard service.isSupported, let keyID = existingKeyID(),
            let decodedKeyID = Data(base64Encoded: keyID),
            decodedKeyID == presentation.keyID
        else { throw PlatformFailure.appAttestUnavailable }
        let clientData = Self.assertionClientDataPrefix + presentation.challengeDigest
        let assertionClientDataHash = Data(SHA256.hash(data: clientData))
        let assertion = try await service.generateAssertion(
            keyID, clientDataHash: assertionClientDataHash
        )
        return try AppleAppAttestAssertionEnvelope(
            ceremonyID: presentation.ceremonyID, assertion: assertion
        )
    }

    /// Produces only the assertion for a locally parsed PXSR/v1 proposal after
    /// its Site-authority signature has been included in the server-compatible
    /// client-data hash. The registered key must be byte-identical; this path
    /// never enrols a replacement device.
    func prepareSiteOriginRelocationAssertion(
        ceremonyID: Data,
        expectedKeyID: Data,
        clientDataHash: Data
    ) async throws -> AppleAppAttestAssertionEnvelope {
        guard service.isSupported, ceremonyID.count == 16,
            expectedKeyID.count == 32, clientDataHash.count == 32,
            let keyID = existingKeyID(), let decodedKeyID = Data(base64Encoded: keyID),
            decodedKeyID == expectedKeyID
        else { throw PlatformFailure.appAttestUnavailable }
        let assertion = try await service.generateAssertion(keyID, clientDataHash: clientDataHash)
        return try AppleAppAttestAssertionEnvelope(ceremonyID: ceremonyID, assertion: assertion)
    }

    /// Produces the raw assertion for the accepted ADR-0014 offline response.
    /// The exact carrier owns its ceremony binding; this method neither enrols
    /// a replacement key nor wraps the assertion in an HTTP ingress envelope.
    func prepareSiteX509FirstProvisionOfflineAssertion(
        expectedKeyID: String,
        clientDataHash: Data
    ) async throws -> Data {
        guard service.isSupported, !expectedKeyID.isEmpty,
            expectedKeyID.utf8.count <= 128, clientDataHash.count == 32,
            let keyID = existingKeyID(), keyID == expectedKeyID
        else { throw PlatformFailure.appAttestUnavailable }
        return try await service.generateAssertion(keyID, clientDataHash: clientDataHash)
    }

    /// Generates and attests a distinct candidate key without changing the
    /// currently admitted App Attest key identifier.
    func stageReplacementKey(
        transactionUUID: Data,
        expectedCurrentKeyID: String,
        clientDataHash: @Sendable (String) throws -> Data
    ) async throws -> (pending: PendingAppAttestReplacementKeyV1, attestation: Data) {
        guard service.isSupported, let localPrimaryKeyID = existingKeyID(),
            PendingAppAttestReplacementKeyV1.canonicalKeyID(expectedCurrentKeyID) != nil,
            PendingAppAttestReplacementKeyV1.canonicalKeyID(localPrimaryKeyID) != nil
        else { throw PlatformFailure.appAttestUnavailable }
        let pending: PendingAppAttestReplacementKeyV1
        if let retained = replacementStore.loadPending() {
            guard retained.transactionUUID == transactionUUID,
                retained.expectedCurrentKeyID == expectedCurrentKeyID,
                retained.localPrimaryKeyID == localPrimaryKeyID,
                retained.canonicalSubmission == nil
            else { throw PlatformFailure.appAttestInvalidInput }
            pending = retained
        } else {
            let replacement = try await service.generateKey()
            pending = try PendingAppAttestReplacementKeyV1(
                transactionUUID: transactionUUID,
                expectedCurrentKeyID: expectedCurrentKeyID,
                localPrimaryKeyID: localPrimaryKeyID,
                replacementKeyID: replacement
            )
            // Publish the candidate identifier before requesting attestation so
            // a crash resumes this exact key rather than minting an untracked
            // second candidate.
            try replacementStore.savePending(pending)
        }
        let hash = try clientDataHash(pending.replacementKeyID)
        guard hash.count == 32, !hash.allSatisfy({ $0 == 0 }) else {
            throw PlatformFailure.appAttestInvalidInput
        }
        return (
            pending,
            try await service.attestKey(pending.replacementKeyID, clientDataHash: hash)
        )
    }

    func commitReplacementKey(
        _ pending: PendingAppAttestReplacementKeyV1,
        authenticated: AuthenticatedAppAttestReplacementAcceptanceV1
    ) throws {
        let accepted = authenticated.accepted
        guard
            let acceptedOldKey = PXARJSON.base64URL(
                accepted.oldKeyIDB64URL, count: 32
            ),
            let acceptedNewKey = PXARJSON.base64URL(
                accepted.newKeyIDB64URL, count: 32
            ),
            PXARJSON.canonicalUUID(accepted.transactionID) == pending.transactionUUID,
            acceptedOldKey.base64EncodedString() == pending.expectedCurrentKeyID,
            acceptedNewKey.base64EncodedString() == pending.replacementKeyID
        else { throw PlatformFailure.appAttestInvalidInput }
        try replacementStore.commitPending(pending)
    }

    func retainReplacementSubmission(
        _ pending: PendingAppAttestReplacementKeyV1,
        canonicalSubmission: Data
    ) throws -> PendingAppAttestReplacementKeyV1 {
        let retained = try pending.retaining(canonicalSubmission: canonicalSubmission)
        try replacementStore.savePending(retained)
        return retained
    }

    func loadRetainedReplacement() -> PendingAppAttestReplacementKeyV1? {
        replacementStore.loadPending()
    }

    func discardReplacementKey(transactionUUID: Data) throws {
        try replacementStore.discardPending(transactionUUID: transactionUUID)
    }

    private func newRegistrationKeyID() async throws -> String {
        let keyID = try await service.generateKey()
        guard Data(base64Encoded: keyID) != nil else {
            throw PlatformFailure.appAttestKeyCreationFailed
        }
        try keyIDStore.saveKeyID(keyID)
        return keyID
    }

    private func attest(keyID: String, clientDataHash: Data) async throws -> Data {
        try await service.attestKey(keyID, clientDataHash: clientDataHash)
    }

    private func existingKeyID() -> String? {
        guard let keyID = keyIDStore.loadKeyID(),
            let decoded = Data(base64Encoded: keyID),
            !decoded.isEmpty,
            decoded.count <= 256
        else { return nil }
        return keyID
    }
}
