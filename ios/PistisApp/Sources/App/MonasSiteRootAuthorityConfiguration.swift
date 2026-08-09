import Foundation

/// Public, signed application configuration for the one Monas Site Root
/// authority that this Pistis build may contact.
///
/// The value is a build-time deployment commitment, not QR, browser, local
/// network, account, or user input. Missing or malformed configuration keeps
/// the Site Root transport unavailable rather than selecting an authority.
struct MonasSiteRootAuthorityConfiguration: Sendable {
    static let infoDictionaryKey = "PistisMonasSiteRootAuthorityOrigin"
    static let spkiInfoDictionaryKey = "PistisMonasSiteRootAuthoritySPKISHA256"

    let authorityOrigin: URL
    let tlsSPKISHA256: Data

    init(rawValue: String, spkiB64URL: String) throws {
        guard !rawValue.isEmpty,
              !rawValue.contains("$("),
              let authorityOrigin = URL(string: rawValue),
              authorityOrigin.absoluteString == rawValue,
              authorityOrigin.scheme == "https",
              authorityOrigin.host != nil,
              authorityOrigin.user == nil,
              authorityOrigin.password == nil,
              authorityOrigin.path.isEmpty,
              authorityOrigin.query == nil,
              authorityOrigin.fragment == nil,
              let tlsSPKISHA256 = Self.decodeCanonicalBase64URL(spkiB64URL),
              tlsSPKISHA256.count == 32,
              !tlsSPKISHA256.allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.invalidConfiguration }
        self.authorityOrigin = authorityOrigin
        self.tlsSPKISHA256 = tlsSPKISHA256
    }

    init(infoDictionary: [String: Any]) throws {
        guard let rawValue = infoDictionary[Self.infoDictionaryKey] as? String,
              let spkiB64URL = infoDictionary[Self.spkiInfoDictionaryKey] as? String
        else {
            throw PlatformFailure.invalidConfiguration
        }
        try self.init(rawValue: rawValue, spkiB64URL: spkiB64URL)
    }

    func makeTransport() throws -> MonasSiteRootDelegationTransport {
        try MonasSiteRootDelegationTransport(
            authorityOrigin: authorityOrigin,
            expectedSPKISHA256: tlsSPKISHA256
        )
    }

    private static func decodeCanonicalBase64URL(_ value: String) -> Data? {
        guard !value.isEmpty,
              !value.contains("$("),
              value.utf8.allSatisfy({
                  ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                      || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95
              }), value.count % 4 != 1
        else { return nil }
        let padding = String(repeating: "=", count: (4 - value.count % 4) % 4)
        let standard = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + padding
        guard let decoded = Data(base64Encoded: standard),
              decoded.base64EncodedString()
                  .replacingOccurrences(of: "+", with: "-")
                  .replacingOccurrences(of: "/", with: "_")
                  .replacingOccurrences(of: "=", with: "") == value
        else { return nil }
        return decoded
    }
}

/// Constructs the sole Site Root transport at application composition. A
/// failed configuration is represented only by the existing unavailable
/// transport; it never becomes a caller-selectable endpoint.
enum ProductionMonasSiteRootTransportFactory {
    static func make(
        infoDictionary: [String: Any] = Bundle.main.infoDictionary ?? [:]
    ) -> any MonasSiteRootCeremonyTransport {
        guard let configuration = try? MonasSiteRootAuthorityConfiguration(
            infoDictionary: infoDictionary
        ), let transport = try? configuration.makeTransport()
        else { return UnavailableMonasSiteRootDelegationTransport() }
        return transport
    }
}
