import Foundation

/// Errors returned by the closed Pistis COSE_Sign1 profile.
public enum CoseSign1Error: Error, Equatable, Sendable {
    case malformed
    case nonCanonical
    case unsupportedProfile
    case invalidKeyID
    case invalidSignature
    case payloadTooLarge
}

/// The production Pistis COSE_Sign1 representation.
///
/// The profile is deliberately closed: an untagged four-element COSE_Sign1
/// array, protected `alg = ES256` and `kid`, an empty unprotected map, an
/// embedded payload, and a fixed-width low-S signature. The payload is
/// preserved byte-for-byte and is never re-encoded here.
public struct CoseSign1: Equatable, Sendable {
    public static let maximumPayloadLength = 65_536

    /// Complete 256-bit Pistis key identifier.
    public let keyID: Data
    /// Exact canonical payload bytes covered by the signature.
    public let payload: Data
    /// Fixed-width COSE `r || s` signature.
    public let signature: Data

    public init(keyID: Data, payload: Data, signature: Data) throws {
        guard keyID.count == 32 else { throw CoseSign1Error.invalidKeyID }
        guard payload.count <= Self.maximumPayloadLength else {
            throw CoseSign1Error.payloadTooLarge
        }
        guard Self.isCanonicalSignature(signature) else {
            throw CoseSign1Error.invalidSignature
        }
        self.keyID = keyID
        self.payload = payload
        self.signature = signature
    }

    /// Encode the sole accepted wire representation.
    public func encoded() -> Data {
        let protected = Self.protectedHeaders(keyID: keyID)
        var result = Data([0x84])
        result.append(CanonicalCBOR.byteString(protected))
        result.append(0xa0)
        result.append(CanonicalCBOR.byteString(payload))
        result.append(CanonicalCBOR.byteString(signature))
        return result
    }

    /// Decode and validate the sole accepted wire representation.
    public static func decode(_ bytes: Data) throws -> Self {
        var cursor = CBORCursor(bytes)
        // Tags, including the commonly used tag 18, are intentionally rejected.
        guard try cursor.readByte() == 0x84 else {
            throw CoseSign1Error.unsupportedProfile
        }
        let protected = try cursor.readByteString()
        let keyID = try parseProtectedHeaders(protected)
        guard try cursor.readByte() == 0xa0 else {
            throw CoseSign1Error.unsupportedProfile
        }
        let payload = try cursor.readByteString(maximum: maximumPayloadLength)
        let signature = try cursor.readByteString(maximum: 64)
        guard cursor.isAtEnd else { throw CoseSign1Error.malformed }
        return try Self(keyID: keyID, payload: payload, signature: signature)
    }

    /// Bytes supplied to ES256 for signing or verification.
    ///
    /// This is the deterministic COSE `Sig_structure` for context
    /// `"Signature1"` and an empty external AAD.
    public func signatureStructure() -> Data {
        Self.uncheckedSignatureStructure(keyID: keyID, payload: payload)
    }

    public static func signatureStructure(keyID: Data, payload: Data) throws -> Data {
        guard keyID.count == 32 else { throw CoseSign1Error.invalidKeyID }
        guard payload.count <= maximumPayloadLength else {
            throw CoseSign1Error.payloadTooLarge
        }
        return uncheckedSignatureStructure(keyID: keyID, payload: payload)
    }

    private static func uncheckedSignatureStructure(keyID: Data, payload: Data) -> Data {
        let protected = protectedHeaders(keyID: keyID)
        var result = Data([0x84])
        result.append(CanonicalCBOR.textString("Signature1"))
        result.append(CanonicalCBOR.byteString(protected))
        result.append(0x40)
        result.append(CanonicalCBOR.byteString(payload))
        return result
    }

    private static func protectedHeaders(keyID: Data) -> Data {
        // {1: -7, 4: h'<32-byte kid>'}, sorted by integer map key.
        var result = Data([0xa2, 0x01, 0x26, 0x04])
        result.append(CanonicalCBOR.byteString(keyID))
        return result
    }

    private static func parseProtectedHeaders(_ bytes: Data) throws -> Data {
        var cursor = CBORCursor(bytes)
        guard try cursor.readByte() == 0xa2,
              try cursor.readByte() == 0x01,
              try cursor.readByte() == 0x26,
              try cursor.readByte() == 0x04
        else {
            throw CoseSign1Error.unsupportedProfile
        }
        let keyID = try cursor.readByteString(maximum: 32)
        guard keyID.count == 32, cursor.isAtEnd else {
            throw CoseSign1Error.invalidKeyID
        }
        return keyID
    }

    private static func isCanonicalSignature(_ signature: Data) -> Bool {
        guard signature.count == 64 else { return false }
        let r = Array(signature.prefix(32))
        let s = Array(signature.suffix(32))
        let order: [UInt8] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
        ]
        guard validScalar(r, below: order), validScalar(s, below: order) else {
            return false
        }
        // floor(P-256 group order / 2), big-endian.
        let halfOrder: [UInt8] = [
            0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
            0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
        ]
        return s.lexicographicallyPrecedes(halfOrder) || s == halfOrder
    }

    private static func validScalar(_ scalar: [UInt8], below order: [UInt8]) -> Bool {
        !scalar.allSatisfy { $0 == 0 } && scalar.lexicographicallyPrecedes(order)
    }
}

private enum CanonicalCBOR {
    static func byteString(_ bytes: Data) -> Data {
        length(major: 2, count: bytes.count) + bytes
    }

    static func textString(_ value: String) -> Data {
        let bytes = Data(value.utf8)
        return length(major: 3, count: bytes.count) + bytes
    }

    private static func length(major: UInt8, count: Int) -> Data {
        precondition(count >= 0)
        if count < 24 {
            return Data([(major << 5) | UInt8(count)])
        }
        if count <= 0xff {
            return Data([(major << 5) | 24, UInt8(count)])
        }
        if count <= 0xffff {
            return Data([
                (major << 5) | 25,
                UInt8((count >> 8) & 0xff),
                UInt8(count & 0xff),
            ])
        }
        return Data([
            (major << 5) | 26,
            UInt8((count >> 24) & 0xff),
            UInt8((count >> 16) & 0xff),
            UInt8((count >> 8) & 0xff),
            UInt8(count & 0xff),
        ])
    }
}

private struct CBORCursor {
    private let bytes: [UInt8]
    private var offset = 0

    init(_ data: Data) {
        bytes = Array(data)
    }

    var isAtEnd: Bool { offset == bytes.count }

    mutating func readByte() throws -> UInt8 {
        guard offset < bytes.count else { throw CoseSign1Error.malformed }
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func readByteString(maximum: Int = Int.max) throws -> Data {
        let initial = try readByte()
        guard initial >> 5 == 2 else { throw CoseSign1Error.malformed }
        let count = try readLength(additional: initial & 0x1f)
        guard count <= maximum else { throw CoseSign1Error.payloadTooLarge }
        guard count <= bytes.count - offset else { throw CoseSign1Error.malformed }
        defer { offset += count }
        return Data(bytes[offset ..< offset + count])
    }

    private mutating func readLength(additional: UInt8) throws -> Int {
        switch additional {
        case 0 ... 23:
            return Int(additional)
        case 24:
            let value = Int(try readByte())
            guard value >= 24 else { throw CoseSign1Error.nonCanonical }
            return value
        case 25:
            let value = (Int(try readByte()) << 8) | Int(try readByte())
            guard value > 0xff else { throw CoseSign1Error.nonCanonical }
            return value
        case 26:
            let value = (Int(try readByte()) << 24)
                | (Int(try readByte()) << 16)
                | (Int(try readByte()) << 8)
                | Int(try readByte())
            guard value > 0xffff else { throw CoseSign1Error.nonCanonical }
            return value
        default:
            throw CoseSign1Error.unsupportedProfile
        }
    }
}
