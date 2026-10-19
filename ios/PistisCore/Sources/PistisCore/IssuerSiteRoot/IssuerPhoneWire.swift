import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Closed signing modes. Their contexts cannot be mixed within an operation.
public enum IssuerPhoneMode: UInt64, Equatable, Sendable { case admission = 1, currentStatusPair = 2 }

/// Parsed comparison DATA; this does not admit a Site, grant or owner.
public struct IssuerPhoneReadiness: Equatable, Sendable {
    public let canonicalBytes: Data
    public let ceremonyID: Data
    public let mode: IssuerPhoneMode
    public let installation: Data
    public let siteID: Data
    public let siteLabel: Data
    public let siteKeyID: Data
    public let authorityID: Data
    public let authorityEpoch: UInt64
    public let keyGeneration: UInt64
    public let keyID: Data
    public let serverExpiry: UInt64
    /// Complete originals remain opaque until the independent owner verifier consumes them.
    public let ownerEvidence: Data
    public let challenge: Data
    public var digest: Data { IssuerPhoneWire.sha256(canonicalBytes) }

    public init(canonicalBytes: Data) throws {
        let a = try IssuerCBOR.decode(canonicalBytes).array(14)
        guard try a[0].uint() == 1, let mode = IssuerPhoneMode(rawValue: try a[2].uint()) else {
            throw IssuerPhoneError.malformed
        }
        self.canonicalBytes = canonicalBytes
        ceremonyID = try a[1].bytes(16, nonzero: true); self.mode = mode
        installation = try a[3].ascii(36 ... 36)
        guard let installationText = String(data: installation, encoding: .ascii),
              let installationID = UUID(uuidString: installationText),
              installationID.uuidString.lowercased() == installationText,
              installationID != UUID(uuid: (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)) else { throw IssuerPhoneError.malformed }
        siteID = try a[4].bytes(16, nonzero: true)
        siteLabel = try a[5].ascii(1 ... 128); siteKeyID = try a[6].bytes(32)
        authorityID = try a[7].bytes(16, nonzero: true); authorityEpoch = try a[8].uint(1 ... UInt64.max)
        keyGeneration = try a[9].uint(1 ... UInt64.max); keyID = try a[10].bytes(32)
        serverExpiry = try a[11].uint(); ownerEvidence = try a[12].bytes(range: 1 ... 245_760)
        challenge = try a[13].bytes(32, nonzero: true)
        if mode == .admission, keyGeneration != 1 { throw IssuerPhoneError.binding }
    }
}

/// A fixed server-selected task, with exact canonical bytes retained for hashing.
public struct IssuerPhoneTask: Equatable, Sendable {
    public enum Kind: UInt64, Equatable, Sendable { case admission = 1, pre = 2, post = 3 }
    public let canonicalBytes: Data
    public let ceremonyID: Data
    public let kind: Kind
    public let ordinal: UInt64
    public let body: IssuerCheckpointBody
    public let preEnvelopeReference: Data
    public let readinessDigest: Data
    public var digest: Data { IssuerPhoneWire.sha256(canonicalBytes) }
    public init(canonicalBytes: Data) throws {
        let a = try IssuerCBOR.decode(canonicalBytes).array(7)
        guard try a[0].uint() == 1, let kind = Kind(rawValue: try a[2].uint()) else { throw IssuerPhoneError.malformed }
        self.canonicalBytes = canonicalBytes; self.kind = kind
        ceremonyID = try a[1].bytes(16, nonzero: true); ordinal = try a[3].uint(1 ... 2)
        body = try IssuerCheckpointBody(canonicalBytes: a[4].bytes(range: 1 ... 8192), kind: kind == .admission ? .admission : .currentStatus)
        preEnvelopeReference = try a[5].bytes(); readinessDigest = try a[6].bytes(32)
        guard (kind == .post && ordinal == 2 && preEnvelopeReference.count == 32)
                || (kind != .post && ordinal == 1 && preEnvelopeReference.isEmpty) else { throw IssuerPhoneError.order }
    }
}

/// The exact adopted request encodings. Every output is bounded canonical CBOR.
public enum IssuerPhoneWire {
    public static let readinessPath = "/auth/pistis/v1/issuer-site-root/readiness"
    public static let exchangePath = "/auth/pistis/v1/issuer-site-root/exchange"
    public static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }
    public static func readinessRequest(mode: IssuerPhoneMode, admissionID: Data, intent: Data, siteKeyID: Data, phoneNonce: Data) throws -> Data {
        guard admissionID.count == 16, admissionID.contains(where: { $0 != 0 }), intent.count == 32,
              intent.contains(where: { $0 != 0 }), siteKeyID.count == 32,
              phoneNonce.count == 32, phoneNonce.contains(where: { $0 != 0 }) else { throw IssuerPhoneError.binding }
        return try IssuerCBOR.array([.unsigned(1), .unsigned(mode.rawValue), .bytes(admissionID), .bytes(intent), .bytes(siteKeyID), .bytes(phoneNonce)]).encoded()
    }
    /// Encode the existing closed current-Site preparation request. This is
    /// comparison DATA; it neither authenticates a caller nor grants permission.
    public static func currentSitePreparationRequest(nonce: Data, currentACKTarget: Data) throws -> Data {
        guard nonce.count == 32, nonce.contains(where: { $0 != 0 }), currentACKTarget.count == 32 else {
            throw IssuerPhoneError.binding
        }
        return try IssuerCBOR.array([.unsigned(1),
            .bytes(Data("issuer-site-current-prepare-v1".utf8)), .bytes(nonce), .bytes(currentACKTarget)]).encoded()
    }
    public static func arm(_ readiness: IssuerPhoneReadiness) throws -> Data {
        try IssuerCBOR.array([.unsigned(1), .unsigned(1), .bytes(readiness.ceremonyID), .bytes(readiness.digest), .unsigned(readiness.mode.rawValue)]).encoded()
    }
    public static func cancel(_ readiness: IssuerPhoneReadiness) throws -> Data {
        try IssuerCBOR.array([.unsigned(1), .unsigned(3), .bytes(readiness.ceremonyID), .bytes(readiness.digest)]).encoded()
    }
    public static func signature(task: IssuerPhoneTask, envelope: Data) throws -> Data {
        guard !envelope.isEmpty, envelope.count <= 16_384 else { throw IssuerPhoneError.bound }
        return try IssuerCBOR.array([.unsigned(1), .unsigned(2), .bytes(task.ceremonyID), .unsigned(task.ordinal), .bytes(task.digest), .bytes(envelope)]).encoded()
    }
    public static func terminal(_ raw: Data, ceremonyID: Data) throws {
        let a = try IssuerCBOR.decode(raw).array(3)
        guard try a[0].uint() == 1, try a[1].bytes(16) == ceremonyID else { throw IssuerPhoneError.binding }
        let result = try a[2].uint(0 ... 2)
        guard result == 0 else { throw result == 1 ? IssuerPhoneError.binding : IssuerPhoneError.unavailable }
    }
}
