import Foundation

/// Closed continuity presentation and approval failures. None is an approval.
public enum ContinuityApprovalError: Error, Equatable, Sendable {
    case malformed, nonCanonical, bound, schema, binding, signature, generation
    case expired, unavailableAuthority, unavailableEnrollment, unavailableLedger
    case conflict, invalidOrder, ambiguousInvocation, retentionFailure
}

// The accepted PMCP subset only. Separate from Pistis COSE and legacy QR codecs.
indirect enum ContinuityValue: Equatable, Sendable {
    case uint(UInt64)
    case bytes(Data)
    case array([ContinuityValue])

    var encoded: Data {
        switch self {
        case .uint(let value): return Self.header(0, value)
        case .bytes(let bytes): return Self.header(2, UInt64(bytes.count)) + bytes
        case .array(let values):
            return values.reduce(Self.header(4, UInt64(values.count))) { $0 + $1.encoded }
        }
    }

    private static func header(_ major: UInt8, _ value: UInt64) -> Data {
        if value < 24 { return Data([major << 5 | UInt8(value)]) }
        let width: Int
        let additional: UInt8
        if value <= 255 { width = 1; additional = 24 }
        else if value <= 65_535 { width = 2; additional = 25 }
        else if value <= 4_294_967_295 { width = 4; additional = 26 }
        else { width = 8; additional = 27 }
        var result = Data([major << 5 | additional])
        for index in (0..<width).reversed() {
            result.append(UInt8(truncatingIfNeeded: value >> (index * 8)))
        }
        return result
    }

    static func decode(_ bytes: Data) throws -> Self {
        guard !bytes.isEmpty, bytes.count <= 4096 else { throw ContinuityApprovalError.bound }
        var reader = ContinuityReader(bytes: Array(bytes))
        let value = try reader.item(depth: 0)
        guard reader.position == bytes.count else { throw ContinuityApprovalError.malformed }
        return value
    }
}

private struct ContinuityReader {
    let bytes: [UInt8]
    var position = 0

    mutating func read(_ length: Int) throws -> ArraySlice<UInt8> {
        guard length >= 0, length <= bytes.count - position else {
            throw ContinuityApprovalError.malformed
        }
        let end = position + length
        defer { position = end }
        return bytes[position..<end]
    }

    mutating func item(depth: Int) throws -> ContinuityValue {
        guard depth <= 16 else { throw ContinuityApprovalError.bound }
        let first = try read(1).first!
        let extra = first & 31
        let value: UInt64
        if extra < 24 { value = UInt64(extra) }
        else {
            guard (24...27).contains(extra) else { throw ContinuityApprovalError.nonCanonical }
            let width = 1 << Int(extra - 24)
            value = try read(width).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            let minimum: UInt64 = width == 1 ? 24 : (width == 2 ? 256 : (width == 4 ? 65_536 : 4_294_967_296))
            guard value >= minimum else { throw ContinuityApprovalError.nonCanonical }
        }
        switch first >> 5 {
        case 0: return .uint(value)
        case 2:
            guard value <= UInt64(bytes.count - position) else { throw ContinuityApprovalError.malformed }
            return .bytes(Data(try read(Int(value))))
        case 4:
            guard depth < 16, value <= 100, value <= UInt64(bytes.count - position) else {
                throw ContinuityApprovalError.bound
            }
            var result: [ContinuityValue] = []
            for _ in 0..<value { result.append(try item(depth: depth + 1)) }
            return .array(result)
        default: throw ContinuityApprovalError.schema
        }
    }
}
