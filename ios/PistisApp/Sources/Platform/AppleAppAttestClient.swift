import CryptoKit
import DeviceCheck
import Foundation

/// The reviewed, purpose-separated registration protocol between Pistis and
/// Monas. This client prepares the request only; it neither submits it nor
/// treats preparation as a successful Monas registration.
struct AppleAppAttestRegistrationEnvelope: Codable, Equatable, Sendable {
    static let protocolVersion = "pistis.apple-app-attest-registration.v1"
    static let reviewedAppIdentifier = "C7A6NQTSY4.org.mnemosynebiosciences.pistis"

    let version: String
    let ceremonyID: String
    let siteTrustDomain: String
    let appIdentifier: String
    let keyIDB64URL: String
    let clientDataHashB64URL: String
    let attestationObjectB64URL: String

    enum CodingKeys: String, CodingKey {
        case version
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

        version = Self.protocolVersion
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
        "\(version) ceremony=\(ceremonyID) site=\(siteTrustDomain) prepared"
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

/// Persists only Apple's opaque key identifier. The private App Attest key is
/// managed by the operating system and is never read, exported, or logged by
/// Pistis.
protocol AppleAppAttestKeyIDStoring: Sendable {
    func loadKeyID() -> String?
    func saveKeyID(_ keyID: String)
}

final class UserDefaultsAppleAppAttestKeyIDStore: AppleAppAttestKeyIDStoring, @unchecked Sendable {
    private static let storageKey = "org.mnemosyne.pistis.apple-app-attest.key-id.v1"
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func loadKeyID() -> String? {
        defaults.string(forKey: Self.storageKey)
    }

    func saveKeyID(_ keyID: String) {
        defaults.set(keyID, forKey: Self.storageKey)
    }
}

/// Apple App Attest adapter for one Monas registration ceremony.
///
/// The raw Monas challenge exists only for the duration of `prepareRegistration`.
/// The returned envelope must be delivered directly to the reviewed Monas
/// authority; callers must not persist, log, or place it in a QR code.
final class AppleAppAttestClient: @unchecked Sendable {
    private let service: DCAppAttestService
    private let keyIDStore: AppleAppAttestKeyIDStoring

    init(
        service: DCAppAttestService = .shared,
        keyIDStore: AppleAppAttestKeyIDStoring = UserDefaultsAppleAppAttestKeyIDStore()
    ) {
        self.service = service
        self.keyIDStore = keyIDStore
    }

    /// Creates a v1 registration envelope for an exact, one-use Monas
    /// ceremony. A caller must retain the raw server challenge only in memory.
    func prepareRegistration(
        ceremonyID: String,
        siteTrustDomain: String,
        serverChallenge: Data
    ) async throws -> AppleAppAttestRegistrationEnvelope {
        guard service.isSupported,
              !serverChallenge.isEmpty,
              serverChallenge.count <= 4_096
        else {
            throw PlatformFailure.appAttestUnavailable
        }

        let keyID = try await existingOrNewKeyID()
        let clientDataHash = Data(SHA256.hash(data: serverChallenge))
        let attestationObject = try await attest(
            keyID: keyID,
            clientDataHash: clientDataHash
        )
        return try AppleAppAttestRegistrationEnvelope(
            ceremonyID: ceremonyID,
            siteTrustDomain: siteTrustDomain,
            appleKeyID: keyID,
            clientDataHash: clientDataHash,
            attestationObject: attestationObject
        )
    }

    private func existingOrNewKeyID() async throws -> String {
        if let existing = keyIDStore.loadKeyID(), Data(base64Encoded: existing) != nil {
            return existing
        }
        let keyID = try await withCheckedThrowingContinuation { continuation in
            service.generateKey { keyID, error in
                if let keyID {
                    continuation.resume(returning: keyID)
                } else {
                    continuation.resume(throwing: error ?? PlatformFailure.appAttestKeyCreationFailed)
                }
            }
        }
        guard Data(base64Encoded: keyID) != nil else {
            throw PlatformFailure.appAttestKeyCreationFailed
        }
        keyIDStore.saveKeyID(keyID)
        return keyID
    }

    private func attest(keyID: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.attestKey(keyID, clientDataHash: clientDataHash) { object, error in
                if let object {
                    continuation.resume(returning: object)
                } else {
                    continuation.resume(throwing: error ?? PlatformFailure.appAttestAttestationFailed)
                }
            }
        }
    }
}
