import Foundation

/// Non-secret public-client configuration for accepted GitHub enrolment.
struct GitHubEnrolmentConfiguration: Equatable, Sendable {
    let clientID: String
    let deviceCodeEndpoint: URL
    let accessTokenEndpoint: URL
    let authenticatedUserEndpoint: URL

    init(
        clientID: String,
        deviceCodeEndpoint: URL,
        accessTokenEndpoint: URL,
        authenticatedUserEndpoint: URL
    ) throws {
        guard (1 ... 128).contains(clientID.utf8.count),
              clientID.utf8.allSatisfy({
                  (65 ... 90).contains($0) || (97 ... 122).contains($0)
                      || (48 ... 57).contains($0)
              }),
              deviceCodeEndpoint.absoluteString
                  == "https://github.com/login/device/code",
              accessTokenEndpoint.absoluteString
                  == "https://github.com/login/oauth/access_token",
              authenticatedUserEndpoint.absoluteString
                  == "https://api.github.com/user"
        else {
            throw PlatformFailure.invalidConfiguration
        }
        self.clientID = clientID
        self.deviceCodeEndpoint = deviceCodeEndpoint
        self.accessTokenEndpoint = accessTokenEndpoint
        self.authenticatedUserEndpoint = authenticatedUserEndpoint
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

enum GitHubEnrolmentState: Equatable, Sendable {
    case unavailable(String)
    case ready
    case authorizing
    case polling
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
            let deviceCode = URL(string: "https://github.com/login/device/code"),
            let accessToken = URL(string: "https://github.com/login/oauth/access_token"),
            let authenticatedUser = URL(string: "https://api.github.com/user"),
            (try? GitHubEnrolmentConfiguration(
                clientID: clientID,
                deviceCodeEndpoint: deviceCode,
                accessTokenEndpoint: accessToken,
                authenticatedUserEndpoint: authenticatedUser
            )) != nil
        else {
            return .init(
                state: .unavailable(
                    "The reviewed GitHub App public client is not configured."
                ),
                configurationLabel: "Configuration missing",
                identityRule: "GitHub numeric account ID is the stable identity.",
                credentialRule: "No GitHub token or client secret is stored by Pistis."
            )
        }
        return .init(
            state: .unavailable(
                "The bounded Device Flow and Prosopikon enrolment ports are not implemented."
            ),
            configurationLabel: "GitHub App public client configuration present",
            identityRule: "GitHub numeric account ID is the stable identity.",
            credentialRule: "No GitHub token or client secret is stored by Pistis."
        )
    }
}
