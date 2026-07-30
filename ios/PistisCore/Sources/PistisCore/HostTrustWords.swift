import Crypto
import Foundation

/// ADR 0029 human-comparable checksum for one authenticated host binding.
public enum HostTrustWordsV1 {
    public static let version: UInt64 = 1

    /// Derive exactly three words from the canonical authenticated facts.
    ///
    /// These words are not authentication material. The caller must still
    /// enforce the complete TLS SPKI digest and authority signature.
    public static func derive(
        authorityID: Data,
        installationID: Data,
        httpsOrigin: String,
        tlsSPKISHA256: Data,
        appConfigurationDigest: Data
    ) throws -> [String] {
        guard authorityID.count == 16, installationID.count == 16,
              tlsSPKISHA256.count == 32, appConfigurationDigest.count == 32
        else { throw FirstDevicePresentationError.malformed }
        let fields = [
            unsigned(0) + unsigned(version),
            unsigned(1) + text("pistis.host-trust-words.v1"),
            unsigned(2) + bytes(authorityID),
            unsigned(3) + bytes(installationID),
            unsigned(4) + text(httpsOrigin),
            unsigned(5) + bytes(tlsSPKISHA256),
            unsigned(6) + bytes(appConfigurationDigest),
        ]
        let canonical = argument(major: 5, value: UInt64(fields.count))
            + fields.reduce(Data(), +)
        let digest = [UInt8](SHA256.hash(data: canonical))
        let indices = [
            Int(digest[0]) << 3 | Int(digest[1]) >> 5,
            Int(digest[1] & 0x1f) << 6 | Int(digest[2]) >> 2,
            Int(digest[2] & 0x03) << 9 | Int(digest[3]) << 1
                | Int(digest[4]) >> 7,
        ]
        let words = try wordList()
        return indices.map { String(words[$0]) }
    }

    private static func wordList() throws -> [Substring] {
        guard let url = Bundle.module.url(
            forResource: "host-trust-words-v1",
            withExtension: "txt"
        ) else { throw FirstDevicePresentationError.malformed }
        let value = try String(contentsOf: url, encoding: .utf8)
        let words = value.split(separator: "\n", omittingEmptySubsequences: false)
        guard words.last == "", words.dropLast().count == 2_048,
              words.dropLast().allSatisfy({
                  !$0.isEmpty && $0.utf8.allSatisfy { (97 ... 122).contains($0) }
              })
        else { throw FirstDevicePresentationError.malformed }
        return Array(words.dropLast())
    }

    private static func unsigned(_ value: UInt64) -> Data {
        argument(major: 0, value: value)
    }

    private static func bytes(_ value: Data) -> Data {
        argument(major: 2, value: UInt64(value.count)) + value
    }

    private static func text(_ value: String) -> Data {
        let encoded = Data(value.utf8)
        return argument(major: 3, value: UInt64(encoded.count)) + encoded
    }

    private static func argument(major: UInt8, value: UInt64) -> Data {
        if value < 24 { return Data([major << 5 | UInt8(value)]) }
        if value <= UInt8.max {
            return Data([major << 5 | 24, UInt8(value)])
        }
        if value <= UInt16.max {
            var encoded = UInt16(value).bigEndian
            return Data([major << 5 | 25])
                + withUnsafeBytes(of: &encoded) { Data($0) }
        }
        if value <= UInt32.max {
            var encoded = UInt32(value).bigEndian
            return Data([major << 5 | 26])
                + withUnsafeBytes(of: &encoded) { Data($0) }
        }
        var encoded = value.bigEndian
        return Data([major << 5 | 27])
            + withUnsafeBytes(of: &encoded) { Data($0) }
    }
}
