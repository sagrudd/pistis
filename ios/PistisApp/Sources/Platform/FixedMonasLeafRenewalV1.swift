import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Joint-authority transcript; parsing does not establish current ownership.
struct FixedMonasLeafRenewalV2 {
    let exactBytes: Data
    let prior: FixedMonasLeafRenewalV1
    let installationUUID: Data
    let devicePoint: Data
    let rootPoint: Data
    let ackPoint: Data

    init(_ data: Data, now: UInt64) throws {
        let bytes = [UInt8](data)
        guard bytes.count >= 8, Array(bytes[0..<8]) == Array("PXRN/v2\u{1}".utf8),
              bytes.count <= 8192 else { throw FixedMonasLeafRenewalV1.Invalid.denied }
        var offset = 8
        func field(_ tag: UInt8) throws -> Data {
            guard offset + 3 <= bytes.count, bytes[offset] == tag else { throw FixedMonasLeafRenewalV1.Invalid.denied }
            let count = Int(bytes[offset + 1]) * 256 + Int(bytes[offset + 2])
            offset += 3
            guard count > 0, count <= bytes.count - offset else { throw FixedMonasLeafRenewalV1.Invalid.denied }
            let result = Data(bytes[offset..<(offset + count)])
            offset += count
            return result
        }
        let prior = try FixedMonasLeafRenewalV1(field(1), now: now)
        let installation = try field(2)
        let device = try field(3), root = try field(4), ack = try field(5)
        func point(_ value: Data) -> Bool { value.count == 33 && (value.first == 2 || value.first == 3) }
        guard offset == bytes.count, prior.ownerGenerations.count == 5,
              prior.ownerGenerations.allSatisfy({ $0 > 0 }), installation.count == 16,
              installation.contains(where: { $0 != 0 }), point(device), point(root), point(ack)
        else { throw FixedMonasLeafRenewalV1.Invalid.denied }
        exactBytes = data; self.prior = prior; installationUUID = installation
        devicePoint = device; rootPoint = root; ackPoint = ack
    }

    enum Role: String { case device, root, ack }
    func rolePayload(_ role: Role) -> Data {
        Data("mnemosyne.fixed-monas-renewal.\(role.rawValue).v2\u{0}".utf8) + exactBytes
    }
}

struct FixedMonasLeafRenewalPresentationV2 {
    let exactBytes: Data
    let statement: FixedMonasLeafRenewalV2
    let addresses: [Data]

    init(_ data: Data, now: UInt64) throws {
        let bytes = [UInt8](data)
        guard bytes.count >= 8, Array(bytes[0..<8]) == Array("PXRW/v2\u{1}".utf8) else {
            throw FixedMonasLeafRenewalV1.Invalid.denied
        }
        var offset = 8
        func field(_ tag: UInt8) throws -> Data {
            guard offset + 3 <= bytes.count, bytes[offset] == tag else { throw FixedMonasLeafRenewalV1.Invalid.denied }
            let count = Int(bytes[offset + 1]) * 256 + Int(bytes[offset + 2]); offset += 3
            guard count > 0, count <= bytes.count - offset else { throw FixedMonasLeafRenewalV1.Invalid.denied }
            let value = Data(bytes[offset..<(offset + count)]); offset += count
            return value
        }
        let joint = try FixedMonasLeafRenewalV2(field(1), now: now)
        let packed = try field(2)
        guard offset == bytes.count else { throw FixedMonasLeafRenewalV1.Invalid.denied }
        var prior = Data("PXRW/v1\u{1}".utf8)
        for (index, value) in [joint.prior.exactBytes, packed].enumerated() {
            guard value.count <= Int(UInt16.max) else { throw FixedMonasLeafRenewalV1.Invalid.denied }
            prior.append(UInt8(index + 1)); prior.append(UInt8(value.count >> 8)); prior.append(UInt8(value.count & 255)); prior.append(value)
        }
        let verified = try FixedMonasLeafRenewalPresentationV1(prior, now: now)
        exactBytes = data; statement = joint; addresses = verified.addresses
    }
}

/// Parsing is not approval: callers must also validate current enrolled trust,
/// compare displayed addresses with the signed digest, and require Face ID.
struct FixedMonasLeafRenewalV1 {
    enum Invalid: Error { case denied }
    static let contentType = "application/vnd.mnemosyne.pxrn.v1"
    let exactBytes: Data
    let siteUUID: Data
    let subjectUUID: Data
    let deviceUUID: Data
    let ownerGenerations: [UInt64]
    let ipSetDigest: Data
    let acknowledgementGeneration: UInt64
    let transaction: Data
    let correlation: Data
    let sessionDigest: Data
    let predecessorLeafDigest: Data
    let predecessorNotAfter: UInt64
    let successorNotAfter: UInt64
    let issuedAt: UInt64
    let expiresAt: UInt64

    func validateCurrentSigner(_ record: SiteRootConvergenceAckRecordV2) throws {
        let site = record.siteUUID.replacingOccurrences(of: "-", with: "").lowercased()
        let actual = siteUUID.map { String(format: "%02x", $0) }.joined()
        guard UUID(uuidString: record.siteUUID) != nil,
              site == actual, record.generation == acknowledgementGeneration else {
            throw Invalid.denied
        }
    }

    init(_ data: Data, now: UInt64) throws {
        let bytes = [UInt8](data)
        guard bytes.count >= 8, Array(bytes[0..<7]) == Array("PXRN/v1".utf8),
              bytes[7] == 1 else { throw Invalid.denied }
        var cursor = 8
        var fields = [[UInt8]]()
        for tag in 1...26 {
            guard cursor + 3 <= bytes.count, bytes[cursor] == UInt8(tag) else {
                throw Invalid.denied
            }
            let length = Int(bytes[cursor + 1]) * 256 + Int(bytes[cursor + 2])
            cursor += 3
            guard length > 0, length <= bytes.count - cursor else { throw Invalid.denied }
            fields.append(Array(bytes[cursor..<(cursor + length)]))
            cursor += length
        }
        func nonzero(_ field: [UInt8], _ count: Int) -> Bool {
            field.count == count && field.contains(where: { $0 != 0 })
        }
        func integer(_ field: [UInt8]) -> UInt64? {
            guard field.count == 8 else { return nil }
            return field.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        }
        func label(_ field: [UInt8]) -> Bool {
            !field.isEmpty && field.count <= 128 && String(bytes: field, encoding: .utf8) != nil
        }
        guard cursor == bytes.count,
              nonzero(fields[0], 16), label(fields[1]),
              fields[2] == Array("service-monas-web".utf8),
              nonzero(fields[3], 32), let ack = integer(fields[4]), ack > 0,
              nonzero(fields[5], 16), nonzero(fields[6], 16),
              [7, 8, 9, 24, 25].allSatisfy({ integer(fields[$0]) != nil }),
              label(fields[10]), label(fields[11]),
              [12, 13, 14, 15, 17, 18, 21].allSatisfy({ nonzero(fields[$0], 32) }),
              fields[14] == fields[18], let oldExpiry = integer(fields[16]), oldExpiry <= now,
              nonzero(fields[19], 16), fields[19][0] & 0x80 == 0,
              fields[20].count == 16,
              let notBefore = integer(Array(fields[20][0..<8])),
              let notAfter = integer(Array(fields[20][8..<16])),
              notAfter > now, notAfter > notBefore, notAfter - notBefore <= 30 * 24 * 60 * 60,
              fields[22].count == 64,
              nonzero(Array(fields[22][0..<16]), 16),
              nonzero(Array(fields[22][16..<32]), 16),
              nonzero(Array(fields[22][32..<64]), 32),
              fields[23].count == 48, nonzero(Array(fields[23][0..<32]), 32),
              let issued = integer(Array(fields[23][32..<40])),
              let expiry = integer(Array(fields[23][40..<48])),
              issued > 0, issued <= now, expiry > now, expiry > issued,
              expiry - issued <= 300 else { throw Invalid.denied }
        exactBytes = data
        siteUUID = Data(fields[0])
        subjectUUID = Data(fields[5])
        deviceUUID = Data(fields[6])
        ownerGenerations = [7, 8, 9, 24, 25].compactMap { integer(fields[$0]) }
        ipSetDigest = Data(fields[3])
        acknowledgementGeneration = ack
        transaction = Data(fields[22][0..<16])
        correlation = Data(fields[22][16..<32])
        sessionDigest = Data(fields[23][0..<32])
        predecessorLeafDigest = Data(fields[15])
        predecessorNotAfter = oldExpiry
        successorNotAfter = notAfter
        issuedAt = issued
        expiresAt = expiry
    }
}

/// Strict display wrapper; its address bytes must hash to the signed statement.
/// The iOS entry point computes SHA-256 itself; the injected helper supports
/// portable parser fixtures only and is not an approval or signing interface.
struct FixedMonasLeafRenewalPresentationV1 {
    let exactBytes: Data
    let statement: FixedMonasLeafRenewalV1
    let addresses: [Data]

    #if canImport(CryptoKit)
    init(_ data: Data, now: UInt64) throws {
        try self.init(data, now: now) { Data(SHA256.hash(data: $0)) }
    }
    #endif

    init(_ data: Data, now: UInt64, sha256: (Data) -> Data) throws {
        let bytes = [UInt8](data)
        guard bytes.count >= 8, Array(bytes[0..<7]) == Array("PXRW/v1".utf8),
              bytes[7] == 1 else { throw FixedMonasLeafRenewalV1.Invalid.denied }
        var cursor = 8
        func field(_ tag: UInt8) throws -> [UInt8] {
            guard cursor + 3 <= bytes.count, bytes[cursor] == tag else {
                throw FixedMonasLeafRenewalV1.Invalid.denied
            }
            let count = Int(bytes[cursor + 1]) * 256 + Int(bytes[cursor + 2])
            cursor += 3
            guard count > 0, count <= bytes.count - cursor else {
                throw FixedMonasLeafRenewalV1.Invalid.denied
            }
            let value = Array(bytes[cursor..<(cursor + count)])
            cursor += count
            return value
        }
        let statement = try FixedMonasLeafRenewalV1(Data(field(1)), now: now)
        let packed = try field(2)
        guard cursor == bytes.count, sha256(Data(packed)) == statement.ipSetDigest else {
            throw FixedMonasLeafRenewalV1.Invalid.denied
        }
        var position = 0
        var values = [[UInt8]]()
        while position < packed.count {
            let count = Int(packed[position])
            position += 1
            guard (count == 4 || count == 16), count <= packed.count - position else {
                throw FixedMonasLeafRenewalV1.Invalid.denied
            }
            let address = Array(packed[position..<(position + count)])
            position += count
            let privateAddress: Bool
            if count == 4 {
                privateAddress = address[0] == 10 ||
                    (address[0] == 172 && (16...31).contains(address[1])) ||
                    (address[0] == 192 && address[1] == 168)
            } else {
                privateAddress = address[0] & 0xfe == 0xfc
            }
            guard privateAddress else { throw FixedMonasLeafRenewalV1.Invalid.denied }
            if let prior = values.last {
                guard prior.count < address.count ||
                        (prior.count == address.count && prior.lexicographicallyPrecedes(address))
                else { throw FixedMonasLeafRenewalV1.Invalid.denied }
            }
            values.append(address)
        }
        guard (1...16).contains(values.count) else { throw FixedMonasLeafRenewalV1.Invalid.denied }
        exactBytes = data
        self.statement = statement
        addresses = values.map { Data($0) }
    }
}
