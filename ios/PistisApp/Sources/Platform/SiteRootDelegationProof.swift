import CryptoKit
import Foundation

/// Versioned public registration material for the separate Site Root key.
///
/// The key is created only through ``SecureEnclaveSigner``. This record has no
/// private material and does not assert Apple App Attest or create authority.
struct SiteRootKeyRegistrationV1: Equatable, Sendable {
    static let schema = "pistis.site-root-key-registration.v1"

    let schema: String
    let deviceKeyID: String
    let publicKeyCompressedSEC1: Data
    let secureEnclaveAttestation: String
}

/// Exact, transient input recovered from the reviewed Monas QR presentation.
///
/// Canonical JSON remains opaque on the phone: this type refuses to re-encode
/// it, so the bytes given to COSE are exactly those supplied by Monas.
struct SiteRootDelegationPresentationV1: Sendable {
    static let schema = "monas.site-root-delegation.v1"
    static let profile = "pistis-secure-enclave-es256-cose-v1"
    static let maximumPayloadLength = 65_536

    let canonicalDelegationJSON: Data
    let deviceKeyID: String
    let submitURL: URL
    let reference: String

    init(
        canonicalDelegationJSON: Data,
        deviceKeyID: String,
        submitURL: URL,
        reference: String
    ) throws {
        guard !canonicalDelegationJSON.isEmpty,
              canonicalDelegationJSON.count <= Self.maximumPayloadLength,
              Self.validIdentifier(deviceKeyID),
              Self.validIdentifier(reference),
              submitURL.scheme == "https",
              submitURL.user == nil,
              submitURL.password == nil,
              submitURL.fragment == nil,
              submitURL.path == "/auth/pistis/site-root-delegations/v1/submit",
              submitURL.query == nil
        else { throw PlatformFailure.invalidConfiguration }

        let object = try StrictJSONObject(
            data: canonicalDelegationJSON,
            maximumBytes: Self.maximumPayloadLength
        ).values
        guard case let .string(schema)? = object["schema"], schema == Self.schema,
              case let .string(profile)? = object["proof_profile"], profile == Self.profile,
              case let .string(keyID)? = object["device_key_id"], keyID == deviceKeyID,
              case let .string(attestation)? = object["secure_enclave_attestation"],
              attestation == "not-asserted"
        else { throw PlatformFailure.invalidConfiguration }
        self.canonicalDelegationJSON = canonicalDelegationJSON
        self.deviceKeyID = deviceKeyID
        self.submitURL = submitURL
        self.reference = reference
    }

    private static func validIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                || ($0 >= 97 && $0 <= 122) || [45, 46, 58, 95].contains($0)
        }
    }
}

/// One detached COSE proof and no network side effect.
struct SiteRootDelegationSubmissionV1: Equatable, Sendable {
    static let schema = "monas.site-root-delegation-submission.v1"

    let schema: String
    let reference: String
    let canonicalDelegationJSON: Data
    let coseSign1: Data

    var coseSign1Base64URL: String {
        coseSign1.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// iPhone-only Site Root registration and detached proof boundary.
///
/// It creates a distinct Secure Enclave key namespace and requires fresh Face
/// ID for each proof. There is no software fallback, private-key export,
/// device attestation fabrication, HTTP transport or server authority.
final class SecureEnclaveSiteRootProofProducer: @unchecked Sendable {
    private let signer: SecureEnclaveSigner

    init(authenticationReason: String) throws {
        signer = try SecureEnclaveSigner(
            namespace: "site-root-delegation-v1",
            authenticationReason: authenticationReason
        )
    }

    func register() throws -> SiteRootKeyRegistrationV1 {
        let publicKey = try signer.create()
        let digest = SHA256.hash(data: publicKey.compressedSEC1)
        return SiteRootKeyRegistrationV1(
            schema: SiteRootKeyRegistrationV1.schema,
            deviceKeyID: "site-root-" + Data(digest).hexadecimalString,
            publicKeyCompressedSEC1: publicKey.compressedSEC1,
            secureEnclaveAttestation: "not-asserted"
        )
    }

    func prove(_ presentation: SiteRootDelegationPresentationV1) throws
        -> SiteRootDelegationSubmissionV1
    {
        let registration = try register()
        guard registration.deviceKeyID == presentation.deviceKeyID else {
            throw PlatformFailure.invalidConfiguration
        }
        let protected = try DetachedES256Cose.protectedHeaders(kid: presentation.deviceKeyID)
        let structure = try DetachedES256Cose.signatureStructure(
            protected: protected,
            payload: presentation.canonicalDelegationJSON
        )
        let signature = try signer.sign(message: structure)
        let coseSign1 = try DetachedES256Cose.envelope(
            protected: protected,
            signature: signature
        )
        return SiteRootDelegationSubmissionV1(
            schema: SiteRootDelegationSubmissionV1.schema,
            reference: presentation.reference,
            canonicalDelegationJSON: presentation.canonicalDelegationJSON,
            coseSign1: coseSign1
        )
    }
}

/// Closed encoding helper for Thesaurophylax's detached ES256 profile.
enum DetachedES256Cose {
    static func protectedHeaders(kid: String) throws -> Data {
        let bytes = Data(kid.utf8)
        guard !bytes.isEmpty, bytes.count <= 128 else {
            throw PlatformFailure.invalidConfiguration
        }
        return Data([0xa2, 0x01, 0x26, 0x04]) + cborByteString(bytes)
    }

    static func signatureStructure(protected: Data, payload: Data) throws -> Data {
        guard !payload.isEmpty, payload.count <= SiteRootDelegationPresentationV1.maximumPayloadLength else {
            throw PlatformFailure.invalidConfiguration
        }
        return Data([0x84]) + cborText("Signature1") + cborByteString(protected)
            + Data([0x40]) + cborByteString(payload)
    }

    static func envelope(protected: Data, signature: Data) throws -> Data {
        guard P256Format.isCanonicalRawSignature(signature) else {
            throw PlatformFailure.malformedSignature
        }
        // Untagged COSE_Sign1 [protected, {}, nil, signature].
        return Data([0x84]) + cborByteString(protected) + Data([0xa0, 0xf6])
            + cborByteString(signature)
    }

    private static func cborText(_ value: String) -> Data { cbor(major: 3, bytes: Data(value.utf8)) }
    private static func cborByteString(_ value: Data) -> Data { cbor(major: 2, bytes: value) }

    private static func cbor(major: UInt8, bytes: Data) -> Data {
        let count = bytes.count
        var result: Data
        if count <= 23 {
            result = Data([major << 5 | UInt8(count)])
        } else if count <= Int(UInt8.max) {
            result = Data([major << 5 | 24, UInt8(count)])
        } else if count <= Int(UInt16.max) {
            result = Data([major << 5 | 25, UInt8(count >> 8), UInt8(count)])
        } else {
            result = Data([major << 5 | 26, UInt8(count >> 24), UInt8(count >> 16), UInt8(count >> 8), UInt8(count)])
        }
        result.append(bytes)
        return result
    }
}

private extension Data {
    var hexadecimalString: String { map { String(format: "%02x", $0) }.joined() }
}
