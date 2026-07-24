import Foundation

public struct BrowserEnrolmentRequest: Equatable, Sendable {
    public let provider: ExternalIdentityProvider
    public let authorizationURL: URL
    public let callbackURL: URL
    public let state: String
    public let pkceVerifier: String

    public init(
        provider: ExternalIdentityProvider,
        authorizationURL: URL,
        callbackURL: URL,
        state: String,
        pkceVerifier: String
    ) throws {
        guard Self.validState(state) else { throw BrowserEnrolmentError.invalidState }
        guard Self.validPKCEVerifier(pkceVerifier) else {
            throw BrowserEnrolmentError.invalidPKCEVerifier
        }
        guard authorizationURL.scheme == "https",
              Self.allowedAuthorizationHost(provider: provider) == authorizationURL.host?.lowercased()
        else {
            throw BrowserEnrolmentError.invalidAuthorizationURL
        }
        guard callbackURL.scheme == "pistis",
              callbackURL.host == "oauth",
              callbackURL.path == "/callback",
              callbackURL.query == nil,
              callbackURL.fragment == nil
        else {
            throw BrowserEnrolmentError.invalidCallbackURL
        }
        self.provider = provider
        self.authorizationURL = authorizationURL
        self.callbackURL = callbackURL
        self.state = state
        self.pkceVerifier = pkceVerifier
    }

    public func validateCallback(_ url: URL) throws -> AuthorizationCallback {
        guard url.scheme == callbackURL.scheme,
              url.host == callbackURL.host,
              url.path == callbackURL.path,
              url.fragment == nil,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        else {
            throw BrowserEnrolmentError.callbackMismatch
        }
        let values = Dictionary(grouping: components.queryItems ?? [], by: \.name)
        guard values["state"]?.count == 1,
              values["state"]?.first?.value == state
        else {
            throw BrowserEnrolmentError.stateMismatch
        }
        let codes = values["code"]?.compactMap(\.value) ?? []
        let errors = values["error"]?.compactMap(\.value) ?? []
        guard !(codes.isEmpty && errors.isEmpty), !(codes.count == 1 && errors.count == 1) else {
            throw BrowserEnrolmentError.malformedCallback
        }
        if let error = errors.first, errors.count == 1 {
            return .providerError(Self.redactedProviderError(error))
        }
        guard codes.count == 1,
              !codes[0].isEmpty,
              codes[0].utf8.count <= 1_024
        else {
            throw BrowserEnrolmentError.malformedCallback
        }
        return .authorizationCode(codes[0])
    }

    private static func allowedAuthorizationHost(provider: ExternalIdentityProvider) -> String {
        switch provider {
        case .github: "github.com"
        case .google: "accounts.google.com"
        }
    }

    private static func validState(_ value: String) -> Bool {
        (32...256).contains(value.utf8.count) && validUnreserved(value)
    }

    private static func validPKCEVerifier(_ value: String) -> Bool {
        (43...128).contains(value.utf8.count) && validUnreserved(value)
    }

    private static func validUnreserved(_ value: String) -> Bool {
        value.utf8.allSatisfy {
            ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) ||
                ($0 >= 48 && $0 <= 57) || [45, 46, 95, 126].contains($0)
        }
    }

    private static func redactedProviderError(_ value: String) -> String {
        switch value {
        case "access_denied", "temporarily_unavailable", "server_error": value
        default: "provider_error"
        }
    }
}

public enum AuthorizationCallback: Equatable, Sendable {
    case authorizationCode(String)
    case providerError(String)
}

public enum BrowserEnrolmentError: Error, Equatable, Sendable {
    case invalidState
    case invalidPKCEVerifier
    case invalidAuthorizationURL
    case invalidCallbackURL
    case callbackMismatch
    case stateMismatch
    case malformedCallback
}
