import Foundation

/// Formats the full eight-byte comparison value; it does not authenticate it.
enum AttendedRecoveryComparison {
    static func expiry(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }

    static func format(_ value: Data) throws -> String {
        guard value.count == 8 else { throw PlatformFailure.invalidConfiguration }
        let hex = value.map { String(format: "%02X", $0) }.joined()
        return stride(from: 0, to: hex.count, by: 4).map { offset in
            let start = hex.index(hex.startIndex, offsetBy: offset)
            return String(hex[start..<hex.index(start, offsetBy: 4)])
        }.joined(separator: "-")
    }
}
