import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Strict adopted body DATA, independent of admission and independent owner checks.
public struct IssuerCheckpointBody: Equatable, Sendable {
    public enum Kind: Equatable, Sendable { case admission, currentStatus }
    public let canonicalBytes: Data
    public let kind: Kind
    let value: IssuerCBOR
    let fields: [IssuerCBOR]
    public var signaturePreimage: Data {
        Data(domain.utf8) + Data([0]) + canonicalBytes
    }
    var domain: String {
        kind == .admission ? "Mnemosyne/Issuer1482/root-admission/v1" : "Mnemosyne/Issuer1482/root-current-status/v1"
    }
    public init(canonicalBytes: Data, kind: Kind) throws {
        let value = try IssuerCBOR.decode(canonicalBytes, maximum: 8192)
        let a = try value.array(kind == .admission ? 21 : 11)
        guard try a[0].bytes() == Data((kind == .admission ? "IADM/1" : "IRCS/1").utf8) else { throw IssuerPhoneError.binding }
        if kind == .admission {
            _ = try a[1].bytes(16, nonzero: true); _ = try a[2].ascii(36 ... 36); _ = try a[3].ascii(1 ... 128)
            guard try a[4].bytes() == Data("classic-commit-status:mnemosyne/expedition".utf8),
                  try a[5].bytes() == Data("thesaurophylax.github-exact-source-qualification-credential-projection.v1".utf8),
                  try a[7].uint() == 1, try a[20].uint() == 1 else { throw IssuerPhoneError.binding }
            _ = try a[6].uint(1 ... UInt64.max)
            for i in [8, 9, 10] { try Self.publicKey(a[i]) }
            try Self.checkpoint(a[11]); try Self.state(a[12])
            for i in [13, 14, 15, 17, 19] { _ = try a[i].bytes(32) }
            _ = try a[16].ascii(1 ... 128); _ = try a[18].ascii(1 ... 128)
        } else {
            _ = try a[1].bytes(32); _ = try a[2].bytes(16)
            _ = try a[3].uint(1 ... UInt64.max); _ = try a[4].uint(1 ... UInt64.max)
            _ = try a[5].bytes(32); _ = try a[6].uint(); _ = try a[7].uint(1 ... 3)
            _ = try a[8].bytes(32, nonzero: true)
            let boot = try a[9].ascii(36 ... 36)
            guard let text = String(data: boot, encoding: .ascii), let uuid = UUID(uuidString: text),
                  uuid.uuidString.lowercased() == text else { throw IssuerPhoneError.malformed }
            _ = try a[10].uint(1 ... UInt64.max)
        }
        self.canonicalBytes = canonicalBytes; self.kind = kind; self.value = value; fields = a
    }
    private static func publicKey(_ node: IssuerCBOR) throws {
        let key = try node.bytes(33)
        guard key.first == 2 || key.first == 3 else { throw IssuerPhoneError.malformed }
        _ = try P256.Signing.PublicKey(compressedRepresentation: key)
    }
    private static func checkpoint(_ node: IssuerCBOR) throws {
        let a = try node.array(5)
        guard try a[0].bytes() == Data("ICKP/1".utf8) else { throw IssuerPhoneError.binding }
        _ = try a[1].uint(); _ = try a[2].bytes(32); _ = try a[3].uint(); _ = try a[4].bytes(32)
    }
    private static func state(_ node: IssuerCBOR) throws {
        let a = try node.array(12)
        guard try a[0].bytes() == Data("IIST/1".utf8) else { throw IssuerPhoneError.binding }
        _ = try a[1].uint(1 ... UInt64.max); _ = try a[2].ascii(0 ... 128); _ = try a[3].bytes(32)
        try checkpoint(a[4]); _ = try a[5].bytes(32); _ = try a[6].bytes(32)
        _ = try a[7].ascii(1 ... 128); _ = try a[8].bytes(32); _ = try a[9].uint(0 ... 3)
        _ = try a[10].uint(); _ = try a[11].uint()
    }

    /// Bind status to the independently prepared current facts. This comparison
    /// is DATA only and cannot construct the platform's private owner handoff.
    public func compareCurrentFacts(revocationRevision: UInt64?, keyState: UInt64?) throws {
        guard kind == .currentStatus, let revocationRevision, let keyState,
              try fields[6].uint() == revocationRevision,
              try fields[7].uint(1 ... 3) == keyState else { throw IssuerPhoneError.binding }
    }

    /// Compare a task with the pinned operation DATA. This is not an owner factory.
    public func compare(to readiness: IssuerPhoneReadiness, rootAdmissionReference: Data?) throws {
        if kind == .admission {
            guard readiness.mode == .admission, try fields[1].bytes() == readiness.authorityID,
                  try fields[2].bytes() == readiness.installation, try fields[3].bytes() == readiness.siteLabel,
                  try fields[6].uint() == readiness.authorityEpoch,
                  IssuerPhoneWire.sha256(try fields[8].bytes()) == readiness.keyID else { throw IssuerPhoneError.binding }
        } else {
            guard readiness.mode == .currentStatusPair, let rootAdmissionReference,
                  rootAdmissionReference.count == 32, try fields[1].bytes() == rootAdmissionReference,
                  try fields[2].bytes() == readiness.authorityID, try fields[3].uint() == readiness.authorityEpoch,
                  try fields[4].uint() == readiness.keyGeneration, try fields[5].bytes() == readiness.keyID else { throw IssuerPhoneError.binding }
        }
    }
}

/// Existing array3 signature format; never COSE and never a second hash at the adapter.
public enum IssuerCheckpointEnvelope {
    public static func encode(body: IssuerCheckpointBody, sitePublicKey: Data, signature: Data) throws -> Data {
        _ = try P256.Signing.PublicKey(compressedRepresentation: sitePublicKey)
        guard sitePublicKey.count == 33, canonicalSignature(signature) else { throw IssuerPhoneError.binding }
        let envelope = try IssuerCBOR.array([body.value, .bytes(IssuerPhoneWire.sha256(sitePublicKey)), .bytes(signature)]).encoded(maximum: 16_384)
        try verify(envelope, body: body, sitePublicKey: sitePublicKey)
        return envelope
    }
    public static func verify(_ envelope: Data, body: IssuerCheckpointBody, sitePublicKey: Data) throws {
        let a = try IssuerCBOR.decode(envelope, maximum: 16_384).array(3)
        let sig = try a[2].bytes(64)
        guard a[0] == body.value, try a[1].bytes(32) == IssuerPhoneWire.sha256(sitePublicKey),
              canonicalSignature(sig) else { throw IssuerPhoneError.binding }
        let key = try P256.Signing.PublicKey(compressedRepresentation: sitePublicKey)
        guard key.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: sig), for: body.signaturePreimage) else {
            throw IssuerPhoneError.binding
        }
    }
    public static func reference(_ envelope: Data, kind: IssuerCheckpointBody.Kind) -> Data {
        let domain = kind == .admission ? "Mnemosyne/Issuer1482/root-admission/v1/envelope" : "Mnemosyne/Issuer1482/root-current-status/v1/envelope"
        return IssuerPhoneWire.sha256(Data(domain.utf8) + Data([0]) + envelope)
    }
    private static func canonicalSignature(_ bytes: Data) -> Bool {
        let half: [UInt8] = [0x7f,0xff,0xff,0xff,0x80,0,0,0,0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xde,0x73,0x7d,0x56,0xd3,0x8b,0xcf,0x42,0x79,0xdc,0xe5,0x61,0x7e,0x31,0x92,0xa8]
        guard bytes.count == 64 else { return false }
        let r = bytes.prefix(32), s = bytes.suffix(32)
        return r.contains(where: { $0 != 0 }) && s.contains(where: { $0 != 0 }) && !half.lexicographicallyPrecedes(s)
    }
}
