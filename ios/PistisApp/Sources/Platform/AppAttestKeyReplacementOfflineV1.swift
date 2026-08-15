import CryptoKit
import Foundation

enum AppAttestKeyReplacementOfflineProfileV1 {
    static let wireProtocol = "pistis.apple-app-attest-key-replacement.v1"
    static let purpose = "site-root-app-attest-key-replacement"
    static let maximumJSONBytes = 196_608
    static let maximumLifetimeMillis: UInt64 = 15 * 60 * 1_000
}

struct AppAttestKeyReplacementPresentationWireV1: Codable, Equatable, Sendable {
    let wireProtocol: String
    let purpose: String
    let transactionID: String
    let installationID: String
    let deviceID: String
    let siteTrustDomain: String
    let oldKeyIDB64URL: String
    let oldGeneration: UInt64
    let newGeneration: UInt64
    let challengeB64URL: String
    let siteRootKeyID: String
    let siteRootPublicKeySEC1B64URL: String
    let issuedAtUnixMillis: UInt64
    let expiresAtUnixMillis: UInt64

    enum CodingKeys: String, CodingKey {
        case wireProtocol = "protocol"
        case purpose
        case transactionID = "transaction_id"
        case installationID = "installation_id"
        case deviceID = "device_id"
        case siteTrustDomain = "site_trust_domain"
        case oldKeyIDB64URL = "old_key_id_b64url"
        case oldGeneration = "old_generation"
        case newGeneration = "new_generation"
        case challengeB64URL = "challenge_b64url"
        case siteRootKeyID = "site_root_key_id"
        case siteRootPublicKeySEC1B64URL = "site_root_public_key_sec1_b64url"
        case issuedAtUnixMillis = "issued_at_unix_millis"
        case expiresAtUnixMillis = "expires_at_unix_millis"
    }
}

struct AppAttestKeyReplacementPresentationV1: Equatable, Sendable {
    let canonical: Data
    let wire: AppAttestKeyReplacementPresentationWireV1
    let transactionUUID: Data
    let oldKeyID: Data
    let challenge: Data
    let siteRootPublicKey: Data

    var digest: Data { Data(SHA256.hash(data: canonical)) }

    init(qrText: String, nowUnixMillis: UInt64) throws {
        guard let bytes = qrText.data(using: .utf8) else {
            throw PlatformFailure.qrPayloadUnsupported
        }
        try self.init(fileBytes: bytes, nowUnixMillis: nowUnixMillis)
    }

    init(fileBytes: Data, nowUnixMillis: UInt64) throws {
        let decoded: AppAttestKeyReplacementPresentationWireV1 = try PXARJSON.decodeCanonical(
            fileBytes,
            maximumBytes: AppAttestKeyReplacementOfflineProfileV1.maximumJSONBytes
        )
        guard decoded.wireProtocol == AppAttestKeyReplacementOfflineProfileV1.wireProtocol,
            decoded.purpose == AppAttestKeyReplacementOfflineProfileV1.purpose,
            let transaction = PXARJSON.canonicalUUID(decoded.transactionID),
            PXARJSON.validIdentifier(decoded.installationID, maximum: 128),
            PXARJSON.validIdentifier(decoded.deviceID, maximum: 128),
            PXARJSON.validIdentifier(decoded.siteTrustDomain, maximum: 253),
            let oldKey = PXARJSON.base64URL(decoded.oldKeyIDB64URL, count: 32),
            decoded.oldGeneration > 0,
            decoded.newGeneration == decoded.oldGeneration + 1,
            let challenge = PXARJSON.base64URL(decoded.challengeB64URL, count: 32),
            PXARJSON.validIdentifier(decoded.siteRootKeyID, maximum: 128),
            let publicKey = PXARJSON.base64URL(
                decoded.siteRootPublicKeySEC1B64URL, count: 33
            ),
            let parsedKey = try? P256.Signing.PublicKey(
                compressedRepresentation: publicKey
            ),
            parsedKey.compressedRepresentation == publicKey,
            decoded.issuedAtUnixMillis <= nowUnixMillis,
            nowUnixMillis < decoded.expiresAtUnixMillis,
            decoded.expiresAtUnixMillis > decoded.issuedAtUnixMillis,
            decoded.expiresAtUnixMillis - decoded.issuedAtUnixMillis
                <= AppAttestKeyReplacementOfflineProfileV1.maximumLifetimeMillis
        else { throw PlatformFailure.qrPayloadUnsupported }
        canonical = fileBytes
        wire = decoded
        transactionUUID = transaction
        oldKeyID = oldKey
        self.challenge = challenge
        siteRootPublicKey = publicKey
    }
}

struct AppAttestKeyReplacementApprovalV1: Codable, Equatable, Sendable {
    let wireProtocol: String
    let purpose: String
    let transactionID: String
    let installationID: String
    let deviceID: String
    let siteTrustDomain: String
    let oldKeyIDB64URL: String
    let newKeyIDB64URL: String
    let attestationSHA256B64URL: String
    let challengeB64URL: String
    let newGeneration: UInt64

    enum CodingKeys: String, CodingKey {
        case wireProtocol = "protocol"
        case purpose
        case transactionID = "transaction_id"
        case installationID = "installation_id"
        case deviceID = "device_id"
        case siteTrustDomain = "site_trust_domain"
        case oldKeyIDB64URL = "old_key_id_b64url"
        case newKeyIDB64URL = "new_key_id_b64url"
        case attestationSHA256B64URL = "attestation_sha256_b64url"
        case challengeB64URL = "challenge_b64url"
        case newGeneration = "new_generation"
    }
}

struct AppAttestKeyReplacementSubmissionV1: Codable, Equatable, Sendable {
    let wireProtocol: String
    let presentation: AppAttestKeyReplacementPresentationWireV1
    let appleRegistration: AppleAppAttestRegistrationEnvelope
    let approval: AppAttestKeyReplacementApprovalV1
    let siteRootSignatureB64URL: String

    enum CodingKeys: String, CodingKey {
        case wireProtocol = "protocol"
        case presentation
        case appleRegistration = "apple_registration"
        case approval
        case siteRootSignatureB64URL = "site_root_signature_b64url"
    }
}

extension AppAttestKeyReplacementSubmissionV1 {
    init(canonicalBytes: Data) throws {
        let decoded: Self = try PXARJSON.decodeCanonical(
            canonicalBytes,
            maximumBytes: AppAttestKeyReplacementOfflineProfileV1.maximumJSONBytes
        )
        guard decoded.wireProtocol == AppAttestKeyReplacementOfflineProfileV1.wireProtocol,
            decoded.presentation.wireProtocol
                == AppAttestKeyReplacementOfflineProfileV1.wireProtocol,
            decoded.presentation.purpose == AppAttestKeyReplacementOfflineProfileV1.purpose,
            decoded.approval.wireProtocol
                == AppAttestKeyReplacementOfflineProfileV1.wireProtocol,
            decoded.approval.purpose == AppAttestKeyReplacementOfflineProfileV1.purpose,
            decoded.approval.transactionID == decoded.presentation.transactionID,
            decoded.approval.installationID == decoded.presentation.installationID,
            decoded.approval.deviceID == decoded.presentation.deviceID,
            decoded.approval.siteTrustDomain == decoded.presentation.siteTrustDomain,
            decoded.approval.oldKeyIDB64URL == decoded.presentation.oldKeyIDB64URL,
            decoded.approval.newGeneration == decoded.presentation.newGeneration,
            decoded.approval.challengeB64URL == decoded.presentation.challengeB64URL,
            decoded.appleRegistration.wireProtocol
                == AppleAppAttestRegistrationEnvelope.protocolVersion,
            decoded.appleRegistration.ceremonyID == decoded.presentation.transactionID,
            decoded.appleRegistration.siteTrustDomain
                == decoded.presentation.siteTrustDomain,
            decoded.appleRegistration.appIdentifier
                == AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            decoded.appleRegistration.keyIDB64URL == decoded.approval.newKeyIDB64URL,
            decoded.appleRegistration.clientDataHashB64URL
                == decoded.presentation.challengeB64URL,
            let attestation = PXARJSON.base64URLVariable(
                decoded.appleRegistration.attestationObjectB64URL,
                minimum: 1,
                maximum: 128 * 1_024
            ),
            decoded.approval.attestationSHA256B64URL
                == PXARJSON.base64URL(Data(SHA256.hash(data: attestation))),
            PXARJSON.base64URL(decoded.siteRootSignatureB64URL, count: 64) != nil
        else { throw PlatformFailure.appAttestInvalidInput }
        self = decoded
    }
}

struct AppAttestKeyReplacementAcceptedV1: Codable, Equatable, Sendable {
    let wireProtocol: String
    let transactionID: String
    let installationID: String
    let oldGeneration: UInt64
    let newGeneration: UInt64
    let oldKeyIDB64URL: String
    let newKeyIDB64URL: String
    let state: String

    enum CodingKeys: String, CodingKey {
        case wireProtocol = "protocol"
        case transactionID = "transaction_id"
        case installationID = "installation_id"
        case oldGeneration = "old_generation"
        case newGeneration = "new_generation"
        case oldKeyIDB64URL = "old_key_id_b64url"
        case newKeyIDB64URL = "new_key_id_b64url"
        case state
    }

    init(canonicalBytes: Data) throws {
        let decoded: Self = try PXARJSON.decodeCanonical(
            canonicalBytes,
            maximumBytes: 4_096
        )
        guard decoded.wireProtocol == AppAttestKeyReplacementOfflineProfileV1.wireProtocol,
            decoded.state == "accepted",
            PXARJSON.canonicalUUID(decoded.transactionID) != nil,
            PXARJSON.validIdentifier(decoded.installationID, maximum: 128),
            decoded.oldGeneration > 0,
            decoded.newGeneration == decoded.oldGeneration + 1,
            PXARJSON.base64URL(decoded.oldKeyIDB64URL, count: 32) != nil,
            PXARJSON.base64URL(decoded.newKeyIDB64URL, count: 32) != nil,
            decoded.oldKeyIDB64URL != decoded.newKeyIDB64URL
        else { throw PlatformFailure.appAttestInvalidInput }
        self = decoded
    }
}

struct StagedAppAttestKeyReplacementResponseV1: Equatable, Sendable {
    let canonicalResponse: Data
    let pendingKey: PendingAppAttestReplacementKeyV1
}

protocol AppAttestKeyReplacementProducingV1: Sendable {
    func produce(
        _ presentation: AppAttestKeyReplacementPresentationV1,
        nowUnixMillis: UInt64
    ) async throws -> StagedAppAttestKeyReplacementResponseV1
}

final class SecureEnclaveAppAttestKeyReplacementProducerV1:
    AppAttestKeyReplacementProducingV1, @unchecked Sendable
{
    private let appAttest: AppleAppAttestClient

    init(appAttest: AppleAppAttestClient = AppleAppAttestClient()) {
        self.appAttest = appAttest
    }

    func produce(
        _ value: AppAttestKeyReplacementPresentationV1,
        nowUnixMillis: UInt64
    ) async throws -> StagedAppAttestKeyReplacementResponseV1 {
        guard value.wire.issuedAtUnixMillis <= nowUnixMillis,
            nowUnixMillis < value.wire.expiresAtUnixMillis
        else { throw PlatformFailure.qrPayloadUnsupported }
        if let retained = appAttest.loadRetainedReplacement(),
           retained.transactionUUID == value.transactionUUID,
           retained.expectedCurrentKeyID == value.oldKeyID.base64EncodedString(),
           let canonicalSubmission = retained.canonicalSubmission
        {
            return StagedAppAttestKeyReplacementResponseV1(
                canonicalResponse: canonicalSubmission,
                pendingKey: retained
            )
        }
        let ceremony = try await FaceIDCeremonyContext.authenticate(
            reason: "Replace this Site's unavailable App Attest key"
        )
        let signer = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: "Approve this exact App Attest key replacement"
        )
        guard try signer.hasExistingKey() else { throw PlatformFailure.keyNotFound }
        let publicKey = try signer.publicKey(using: ceremony).compressedSEC1
        guard publicKey == value.siteRootPublicKey else {
            throw PlatformFailure.keyNotFound
        }

        let expectedCurrent = value.oldKeyID.base64EncodedString()
        let staged = try await appAttest.stageReplacementKey(
            transactionUUID: value.transactionUUID,
            expectedCurrentKeyID: expectedCurrent,
            clientDataHash: { _ in value.challenge }
        )
        guard let replacement = Data(base64Encoded: staged.pending.replacementKeyID),
            replacement.count == 32,
            replacement != value.oldKeyID
        else { throw PlatformFailure.appAttestInvalidInput }
        let newKeyID = PXARJSON.base64URL(replacement)
        let approval = AppAttestKeyReplacementApprovalV1(
            wireProtocol: AppAttestKeyReplacementOfflineProfileV1.wireProtocol,
            purpose: AppAttestKeyReplacementOfflineProfileV1.purpose,
            transactionID: value.wire.transactionID,
            installationID: value.wire.installationID,
            deviceID: value.wire.deviceID,
            siteTrustDomain: value.wire.siteTrustDomain,
            oldKeyIDB64URL: value.wire.oldKeyIDB64URL,
            newKeyIDB64URL: newKeyID,
            attestationSHA256B64URL: PXARJSON.base64URL(
                Data(SHA256.hash(data: staged.attestation))
            ),
            challengeB64URL: value.wire.challengeB64URL,
            newGeneration: value.wire.newGeneration
        )
        let approvalBytes = try PXARJSON.encodeCanonical(approval)
        let signature = try signer.sign(message: approvalBytes, using: ceremony)
        guard signature.count == 64 else { throw PlatformFailure.appAttestInvalidInput }
        let registration = try AppleAppAttestRegistrationEnvelope(
            ceremonyID: value.wire.transactionID,
            siteTrustDomain: value.wire.siteTrustDomain,
            appleKeyID: staged.pending.replacementKeyID,
            clientDataHash: value.challenge,
            attestationObject: staged.attestation
        )
        let submission = AppAttestKeyReplacementSubmissionV1(
            wireProtocol: AppAttestKeyReplacementOfflineProfileV1.wireProtocol,
            presentation: value.wire,
            appleRegistration: registration,
            approval: approval,
            siteRootSignatureB64URL: PXARJSON.base64URL(signature)
        )
        let response = try PXARJSON.encodeCanonical(submission)
        guard response.count <= AppAttestKeyReplacementOfflineProfileV1.maximumJSONBytes else {
            throw PlatformFailure.appAttestInvalidInput
        }
        let retained = try appAttest.retainReplacementSubmission(
            staged.pending, canonicalSubmission: response
        )
        return StagedAppAttestKeyReplacementResponseV1(
            canonicalResponse: response,
            pendingKey: retained
        )
    }
}

enum PXARJSON {
    static func encodeCanonical<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }

    static func decodeCanonical<T: Codable>(
        _ bytes: Data,
        maximumBytes: Int
    ) throws -> T {
        guard !bytes.isEmpty, bytes.count <= maximumBytes else {
            throw PlatformFailure.qrPayloadUnsupported
        }
        let value: T
        do { value = try JSONDecoder().decode(T.self, from: bytes) } catch {
            throw PlatformFailure.qrPayloadUnsupported
        }
        guard try encodeCanonical(value) == bytes else {
            throw PlatformFailure.qrPayloadUnsupported
        }
        return value
    }

    static func canonicalUUID(_ value: String) -> Data? {
        guard let parsed = UUID(uuidString: value),
            parsed.uuidString.lowercased() == value
        else { return nil }
        var uuid = parsed.uuid
        return withUnsafeBytes(of: &uuid) { Data($0) }
    }

    static func validIdentifier(_ value: String, maximum: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximum
            && value.utf8.allSatisfy { (0x21...0x7e).contains($0) }
    }

    static func base64URL(_ value: String, count: Int) -> Data? {
        base64URLVariable(value, minimum: count, maximum: count)
    }

    static func base64URLVariable(
        _ value: String,
        minimum: Int,
        maximum: Int
    ) -> Data? {
        guard !value.isEmpty, !value.contains("="), value.utf8.allSatisfy({ $0.isBase64URL })
        else { return nil }
        let standard =
            value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let decoded = Data(base64Encoded: standard),
            (minimum...maximum).contains(decoded.count),
            base64URL(decoded) == value
        else { return nil }
        return decoded
    }

    static func base64URL(_ value: Data) -> String {
        value.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

extension UInt8 {
    fileprivate var isBase64URL: Bool {
        (48...57).contains(self) || (65...90).contains(self)
            || (97...122).contains(self) || self == 45 || self == 95
    }
}
