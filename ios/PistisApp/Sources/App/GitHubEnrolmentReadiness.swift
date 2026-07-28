import Foundation

/// Non-secret public-client configuration for accepted GitHub enrolment.
struct GitHubEnrolmentConfiguration: Equatable, Sendable {
    let clientID: String
    let authorizationEndpoint: URL
    let callbackURL: URL
    let brokerExchangeEndpoint: URL

    init(
        clientID: String,
        authorizationEndpoint: URL,
        callbackURL: URL,
        brokerExchangeEndpoint: URL
    ) throws {
        guard (1 ... 128).contains(clientID.utf8.count),
              clientID.utf8.allSatisfy({
                  (65 ... 90).contains($0) || (97 ... 122).contains($0)
                      || (48 ... 57).contains($0)
              }),
              authorizationEndpoint.absoluteString
                  == "https://github.com/login/oauth/authorize",
              callbackURL.absoluteString == "pistis://oauth/callback",
              brokerExchangeEndpoint.scheme == "https",
              brokerExchangeEndpoint.host != nil,
              brokerExchangeEndpoint.user == nil,
              brokerExchangeEndpoint.password == nil,
              brokerExchangeEndpoint.query == nil,
              brokerExchangeEndpoint.fragment == nil
        else {
            throw PlatformFailure.invalidConfiguration
        }
        self.clientID = clientID
        self.authorizationEndpoint = authorizationEndpoint
        self.callbackURL = callbackURL
        self.brokerExchangeEndpoint = brokerExchangeEndpoint
    }
}

/// Credential-free result returned by the trusted exchange/binding authority.
///
/// The mobile app never receives a provider access token through this port.
struct GitHubStableIdentityProof: Equatable, Sendable {
    let numericSubject: UInt64
    let displayLogin: String

    init(numericSubject: UInt64, displayLogin: String) throws {
        let trimmed = displayLogin.trimmingCharacters(in: .whitespacesAndNewlines)
        guard numericSubject > 0,
              trimmed == displayLogin,
              (1 ... 128).contains(displayLogin.utf8.count),
              displayLogin.unicodeScalars.allSatisfy({
                  !CharacterSet.controlCharacters.contains($0)
              })
        else {
            throw PlatformFailure.invalidConfiguration
        }
        self.numericSubject = numericSubject
        self.displayLogin = displayLogin
    }
}

/// Disabled authority port required before browser enrolment can be enabled.
protocol GitHubBrokerExchanging: Sendable {
    func exchange(
        _ authorization: OAuthAuthorizationCode,
        endpoint: URL
    ) async throws -> GitHubStableIdentityProof
}

enum GitHubEnrolmentState: Equatable, Sendable {
    case unavailable(String)
    case ready
    case authorizing
    case exchanging
    case enrolled(GitHubStableIdentityProof)
    case failed(String)

    var mayStart: Bool {
        self == .ready
    }
}

struct GitHubEnrolmentReadiness: Equatable, Sendable {
    let state: GitHubEnrolmentState
    let configurationLabel: String
    let identityRule: String
    let credentialRule: String

    static func current(bundle: Bundle = .main) -> Self {
        guard let clientID = bundle.object(
            forInfoDictionaryKey: "PistisGitHubClientID"
        ) as? String,
            let brokerText = bundle.object(
                forInfoDictionaryKey: "PistisGitHubBrokerExchangeURL"
            ) as? String,
            let authorization = URL(string: "https://github.com/login/oauth/authorize"),
            let callback = URL(string: "pistis://oauth/callback"),
            let broker = URL(string: brokerText),
            (try? GitHubEnrolmentConfiguration(
                clientID: clientID,
                authorizationEndpoint: authorization,
                callbackURL: callback,
                brokerExchangeEndpoint: broker
            )) != nil
        else {
            return .init(
                state: .unavailable(
                    "The reviewed GitHub OAuth client and confidential broker are not configured."
                ),
                configurationLabel: "Configuration missing",
                identityRule: "GitHub numeric account ID is the stable identity.",
                credentialRule: "No GitHub token or client secret is stored by Pistis."
            )
        }
        return .init(
            state: .unavailable(
                "The broker response and Prosopikon enrolment ports are not implemented."
            ),
            configurationLabel: "Public client configuration present",
            identityRule: "GitHub numeric account ID is the stable identity.",
            credentialRule: "No GitHub token or client secret is stored by Pistis."
        )
    }
}
