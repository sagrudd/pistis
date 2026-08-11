import Foundation

/// Public, signed application configuration for the one Monas Site Root
/// authority that this Pistis build may contact.
///
/// The value is a build-time deployment commitment, not QR, browser, local
/// network, account, or user input. Missing or malformed configuration keeps
/// the Site Root transport unavailable rather than selecting an authority.
struct MonasSiteRootAuthorityConfiguration: Sendable {
    static let infoDictionaryKey = "PistisMonasSiteRootAuthorityOrigin"
    static let trustModeInfoDictionaryKey = "PistisMonasSiteRootAuthorityTrustMode"
    static let spkiInfoDictionaryKey = "PistisMonasSiteRootAuthoritySPKISHA256"
    static let rootDERInfoDictionaryKey = "PistisMonasSiteRootAuthorityRootDERB64URL"
    static let rootFingerprintInfoDictionaryKey =
        "PistisMonasSiteRootAuthorityRootSHA256B64URL"
    static let rootGenerationInfoDictionaryKey = "PistisMonasSiteRootAuthorityRootGeneration"

    static let bootstrapTrustMode = "bootstrap-leaf-spki-v1"
    static let siteRootTrustMode = "site-root-generation-v1"

    let authorityOrigin: URL
    let trustPolicy: MonasServerTrustPolicy

    init(rawValue: String, spkiB64URL: String) throws {
        guard let tlsSPKISHA256 = Self.decodeCanonicalBase64URL(spkiB64URL),
              tlsSPKISHA256.count == 32,
              !tlsSPKISHA256.allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.invalidConfiguration }
        try self.init(rawValue: rawValue, trustPolicy: .bootstrapLeafSPKI(tlsSPKISHA256))
    }

    init(infoDictionary: [String: Any]) throws {
        guard let rawValue = infoDictionary[Self.infoDictionaryKey] as? String,
              let trustMode = infoDictionary[Self.trustModeInfoDictionaryKey] as? String
        else {
            throw PlatformFailure.invalidConfiguration
        }
        switch trustMode {
        case Self.bootstrapTrustMode:
            guard let spki = infoDictionary[Self.spkiInfoDictionaryKey] as? String,
                  Self.empty(infoDictionary[Self.rootDERInfoDictionaryKey]),
                  Self.empty(infoDictionary[Self.rootFingerprintInfoDictionaryKey]),
                  Self.empty(infoDictionary[Self.rootGenerationInfoDictionaryKey])
            else { throw PlatformFailure.invalidConfiguration }
            try self.init(rawValue: rawValue, spkiB64URL: spki)
        case Self.siteRootTrustMode:
            guard Self.empty(infoDictionary[Self.spkiInfoDictionaryKey]),
                  let rootText = infoDictionary[Self.rootDERInfoDictionaryKey] as? String,
                  let fingerprintText = infoDictionary[Self.rootFingerprintInfoDictionaryKey]
                    as? String,
                  let generationText = infoDictionary[Self.rootGenerationInfoDictionaryKey]
                    as? String,
                  let generation = UInt64(generationText), generation > 0,
                  let rootDER = Self.decodeCanonicalBase64URL(rootText),
                  let fingerprint = Self.decodeCanonicalBase64URL(fingerprintText)
            else { throw PlatformFailure.invalidConfiguration }
            try self.init(
                rawValue: rawValue,
                trustPolicy: MonasServerTrustPolicy(
                    siteRootDER: rootDER,
                    fingerprintSHA256: fingerprint,
                    generation: generation
                )
            )
        default:
            throw PlatformFailure.invalidConfiguration
        }
    }

    private init(rawValue: String, trustPolicy: MonasServerTrustPolicy) throws {
        guard !rawValue.isEmpty, !rawValue.contains("$("),
              let origin = URL(string: rawValue), origin.absoluteString == rawValue,
              origin.scheme == "https", origin.host != nil,
              origin.user == nil, origin.password == nil, origin.path.isEmpty,
              origin.query == nil, origin.fragment == nil
        else { throw PlatformFailure.invalidConfiguration }
        authorityOrigin = origin
        self.trustPolicy = trustPolicy
    }

    func makeTransport() throws -> MonasSiteRootDelegationTransport {
        try MonasSiteRootDelegationTransport(
            authorityOrigin: authorityOrigin,
            trustPolicy: trustPolicy
        )
    }

    private static func empty(_ value: Any?) -> Bool {
        value == nil || (value as? String)?.isEmpty == true
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
