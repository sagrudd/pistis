import Foundation

/// Public, signed application configuration for the one Monas Site Root
/// authority that this Pistis build may contact.
///
/// The value is a build-time deployment commitment, not QR, browser, local
/// network, account, or user input. Missing or malformed configuration keeps
/// the Site Root transport unavailable rather than selecting an authority.
struct MonasSiteRootAuthorityConfiguration: Sendable {
    static let infoDictionaryKey = "PistisMonasSiteRootAuthorityOrigin"

    let authorityOrigin: URL

    init(rawValue: String) throws {
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
              authorityOrigin.fragment == nil
        else { throw PlatformFailure.invalidConfiguration }
        self.authorityOrigin = authorityOrigin
    }

    init(infoDictionary: [String: Any]) throws {
        guard let rawValue = infoDictionary[Self.infoDictionaryKey] as? String else {
            throw PlatformFailure.invalidConfiguration
        }
        try self.init(rawValue: rawValue)
    }

    func makeTransport() throws -> MonasSiteRootDelegationTransport {
        try MonasSiteRootDelegationTransport(authorityOrigin: authorityOrigin)
    }
}

/// Constructs the sole Site Root transport at application composition. A
/// failed configuration is represented only by the existing unavailable
/// transport; it never becomes a caller-selectable endpoint.
enum ProductionMonasSiteRootTransportFactory {
    static func make(
        infoDictionary: [String: Any] = Bundle.main.infoDictionary ?? [:]
    ) -> any MonasSiteRootDelegationSubmitting {
        guard let configuration = try? MonasSiteRootAuthorityConfiguration(
            infoDictionary: infoDictionary
        ), let transport = try? configuration.makeTransport()
        else { return UnavailableMonasSiteRootDelegationTransport() }
        return transport
    }
}
