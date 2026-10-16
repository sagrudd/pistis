import Foundation

/// Failures of the closed ADR 0045 phone operation. No field contents are logged.
public enum IssuerPhoneError: Error, Equatable, Sendable {
    case malformed, bound, binding, expired, order, uncertain, unavailable
}

/// The only value families permitted by the adopted phone protocol.
indirect enum IssuerCBOR: Equatable, Sendable {
    case unsigned(UInt64), bytes(Data), array([IssuerCBOR])

    static func decode(_ raw: Data, maximum: Int = 262_144) throws -> Self {
        guard !raw.isEmpty, raw.count <= maximum else { throw IssuerPhoneError.bound }
        let bytes = [UInt8](raw)
        var offset = 0
        var nodes = 0
        func read(_ depth: Int) throws -> Self {
            nodes += 1
            guard depth <= 12, nodes <= 16_384, offset < bytes.count else {
                throw IssuerPhoneError.bound
            }
            let first = bytes[offset]; offset += 1
            let major = first >> 5, tag = first & 31
            guard [UInt8(0), 2, 4].contains(major), tag <= 27 else {
                throw IssuerPhoneError.malformed
            }
            var length = UInt64(tag)
            if tag >= 24 {
                let width = 1 << Int(tag - 24)
                guard offset <= bytes.count - width else { throw IssuerPhoneError.malformed }
                length = 0
                for _ in 0 ..< width { length = length << 8 | UInt64(bytes[offset]); offset += 1 }
                let minimum: UInt64 = [24, 256, 65_536, 4_294_967_296][Int(tag - 24)]
                guard length >= minimum else { throw IssuerPhoneError.malformed }
            }
            switch major {
            case 0: return .unsigned(length)
            case 2:
                guard length <= UInt64(bytes.count - offset) else { throw IssuerPhoneError.bound }
                let end = offset + Int(length)
                let value = Data(bytes[offset ..< end]); offset = end
                return .bytes(value)
            default:
                // Check before allocation; every element costs at least one node and byte.
                guard length <= UInt64(16_384 - nodes), length <= UInt64(bytes.count - offset) else {
                    throw IssuerPhoneError.bound
                }
                var values: [Self] = []
                for _ in 0 ..< Int(length) { values.append(try read(depth + 1)) }
                return .array(values)
            }
        }
        let value = try read(0)
        guard offset == bytes.count, try value.encoded(maximum: maximum) == raw else {
            throw IssuerPhoneError.malformed
        }
        return value
    }

    func encoded(maximum: Int = 262_144) throws -> Data {
        // Bound the full tree before recursive encoding or output allocation.
        var pending: [(Self, Int)] = [(self, 0)]
        var nodes = 0, length = 0
        func headerLength(_ n: UInt64) -> Int { n < 24 ? 1 : n <= 255 ? 2 : n <= 65_535 ? 3 : n <= 4_294_967_295 ? 5 : 9 }
        while let (value, depth) = pending.popLast() {
            nodes += 1
            guard nodes <= 16_384, depth <= 12 else { throw IssuerPhoneError.bound }
            switch value {
            case let .unsigned(n): length += headerLength(n)
            case let .bytes(b):
                guard b.count <= maximum else { throw IssuerPhoneError.bound }
                length += headerLength(UInt64(b.count)) + b.count
            case let .array(a):
                guard a.count <= 16_384 - nodes else { throw IssuerPhoneError.bound }
                length += headerLength(UInt64(a.count))
                pending.append(contentsOf: a.map { ($0, depth + 1) })
            }
            guard length <= maximum else { throw IssuerPhoneError.bound }
        }
        func head(_ major: UInt8, _ n: UInt64) -> Data {
            if n < 24 { return Data([major << 5 | UInt8(n)]) }
            let width = n <= 255 ? 1 : n <= 65_535 ? 2 : n <= 4_294_967_295 ? 4 : 8
            let tag: UInt8 = width == 1 ? 24 : width == 2 ? 25 : width == 4 ? 26 : 27
            var out = Data([major << 5 | tag])
            for byte in stride(from: width - 1, through: 0, by: -1) { out.append(UInt8(truncatingIfNeeded: n >> (byte * 8))) }
            return out
        }
        func emit(_ value: Self) -> Data {
            switch value {
            case let .unsigned(n): return head(0, n)
            case let .bytes(b): return head(2, UInt64(b.count)) + b
            case let .array(a): return a.reduce(into: head(4, UInt64(a.count))) { $0.append(emit($1)) }
            }
        }
        return emit(self)
    }

    func array(_ count: Int) throws -> [Self] {
        guard case let .array(a) = self, a.count == count else { throw IssuerPhoneError.malformed }
        return a
    }
    func bytes(_ count: Int? = nil, range: ClosedRange<Int>? = nil, nonzero: Bool = false) throws -> Data {
        guard case let .bytes(b) = self, count.map({ b.count == $0 }) ?? true,
              range.map({ $0.contains(b.count) }) ?? true,
              !nonzero || b.contains(where: { $0 != 0 }) else { throw IssuerPhoneError.malformed }
        return b
    }
    func uint(_ allowed: ClosedRange<UInt64> = 0 ... UInt64.max) throws -> UInt64 {
        guard case let .unsigned(n) = self, allowed.contains(n) else { throw IssuerPhoneError.malformed }
        return n
    }
    func ascii(_ range: ClosedRange<Int>) throws -> Data {
        let b = try bytes(range: range)
        guard b.allSatisfy({ 32 ... 126 ~= $0 }) else { throw IssuerPhoneError.malformed }
        return b
    }
}
