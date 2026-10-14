import Crypto
import Foundation

/// Closed approval objects. These do not reuse a legacy consent or COSE purpose.
public enum ContinuityApprovalKind: String, CaseIterable, Hashable, Sendable {
    case descriptor = "PCCB/1"
    case selection = "PCMS/1"
    case issuer = "PCII/1"

    var signatureDomain: String {
        switch self {
        case .descriptor: "Mnemosyne/Proxenos/continuity-custody-binding-signature/v1"
        case .selection: "Mnemosyne/Proxenos/continuity-mode-selection-signature/v1"
        case .issuer: "Mnemosyne/Proxenos/continuity-issuer/v1"
        }
    }
}

func continuityDigest(_ domain: String, _ bytes: Data) -> Data {
    Data(SHA256.hash(data: Data(domain.utf8) + Data([0]) + bytes))
}

func continuityKeyID(_ key: Data) throws -> Data {
    guard key.count == 33, key.first == 2 || key.first == 3,
          (try? P256.Signing.PublicKey(compressedRepresentation: key)) != nil
    else { throw ContinuityApprovalError.signature }
    return Data(SHA256.hash(data: key))
}

struct ContinuitySignedEnvelope: Sendable {
    let bytes: Data
    let body: ContinuityValue
    let keyID: Data
    let signature: Data

    init(_ bytes: Data, kind: ContinuityApprovalKind, publicKey: Data) throws {
        let fields = try ContinuityValue.decode(bytes).fields(3)
        guard case .array = fields[0], try fields[0].fields().first?.ascii() == kind.rawValue
        else { throw ContinuityApprovalError.schema }
        body = fields[0]
        keyID = try fields[1].data(32)
        signature = try fields[2].data(64)
        guard keyID == (try continuityKeyID(publicKey)), Self.lowS(signature) else {
            throw ContinuityApprovalError.signature
        }
        let key = try P256.Signing.PublicKey(compressedRepresentation: publicKey)
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        let prehash = SHA256.hash(data: Data(kind.signatureDomain.utf8) + Data([0]) + body.encoded)
        guard key.isValidSignature(sig, for: prehash) else { throw ContinuityApprovalError.signature }
        self.bytes = bytes
    }

    // Same fixed P256 scalar boundaries as the existing closed Pistis codec.
    static func lowS(_ signature: Data) -> Bool {
        guard signature.count == 64 else { return false }
        let order = continuityHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
        let half = continuityHex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")
        let r = Data(signature.prefix(32)), s = Data(signature.suffix(32))
        return !r.allSatisfy({ $0 == 0 }) && !s.allSatisfy({ $0 == 0 })
            && r.lexicographicallyPrecedes(order) && s.lexicographicallyPrecedes(order)
            && (s == half || s.lexicographicallyPrecedes(half))
    }
}

func continuityHex(_ text: String) -> Data {
    let bytes = Array(text.utf8)
    var result = Data()
    for i in stride(from: 0, to: bytes.count, by: 2) {
        result.append(UInt8(String(decoding: bytes[i..<i + 2], as: UTF8.self), radix: 16)!)
    }
    return result
}

extension ContinuityValue {
    func fields(_ count: Int? = nil) throws -> [ContinuityValue] {
        guard case .array(let values) = self, count == nil || values.count == count else {
            throw ContinuityApprovalError.schema
        }
        return values
    }
    func data(_ length: Int? = nil) throws -> Data {
        guard case .bytes(let bytes) = self, length == nil || bytes.count == length else {
            throw ContinuityApprovalError.schema
        }
        return bytes
    }
    func number() throws -> UInt64 {
        guard case .uint(let value) = self else { throw ContinuityApprovalError.schema }
        return value
    }
    func ascii() throws -> String {
        let bytes = try data()
        guard !bytes.isEmpty, bytes.allSatisfy({ (32...126).contains($0) }),
              let text = String(data: bytes, encoding: .ascii)
        else { throw ContinuityApprovalError.schema }
        return text
    }
}
