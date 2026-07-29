import Foundation

/// Non-secret public-client configuration for accepted GitHub enrolment.
struct GitHubEnrolmentConfiguration: Equatable, Sendable {
    static let reviewedClientID = "Iv23lievHWZTGyot0BXa"
    static let verificationURI = URL(string: "https://github.com/login/device")!

    let clientID: String
    let deviceCodeEndpoint: URL
    let accessTokenEndpoint: URL
    let authenticatedUserEndpoint: URL
    let apiVersion: String
    let appConfigurationDigest: Data

    init(
        clientID: String,
        deviceCodeEndpoint: URL,
        accessTokenEndpoint: URL,
        authenticatedUserEndpoint: URL,
        apiVersion: String,
        appConfigurationDigest: Data
    ) throws {
        let apiVersionBytes = Array(apiVersion.utf8)
        guard clientID == Self.reviewedClientID,
            deviceCodeEndpoint.absoluteString
                == "https://github.com/login/device/code",
            accessTokenEndpoint.absoluteString
                == "https://github.com/login/oauth/access_token",
            authenticatedUserEndpoint.absoluteString
                == "https://api.github.com/user",
            apiVersionBytes.count == 10,
            apiVersionBytes.enumerated().allSatisfy { index, byte in
                [4, 7].contains(index) ? byte == 0x2d : (0x30...0x39).contains(byte)
            },
            appConfigurationDigest.count == 32
        else {
            throw PlatformFailure.invalidConfiguration
        }
        self.clientID = clientID
        self.deviceCodeEndpoint = deviceCodeEndpoint
        self.accessTokenEndpoint = accessTokenEndpoint
        self.authenticatedUserEndpoint = authenticatedUserEndpoint
        self.apiVersion = apiVersion
        self.appConfigurationDigest = appConfigurationDigest
    }
}

/// Credential-free result returned by the trusted exchange/binding authority.
///
/// The mobile app never receives a provider access token through this port.
struct GitHubStableIdentityProof: Equatable, Sendable {
    let numericSubject: UInt64
    let displayLogin: String?

    init(numericSubject: UInt64, displayLogin: String?) throws {
        let trimmed = displayLogin?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard numericSubject > 0,
            trimmed == displayLogin,
            displayLogin.map({ (1...128).contains($0.utf8.count) }) ?? true,
            displayLogin?.unicodeScalars.allSatisfy({
                !CharacterSet.controlCharacters.contains($0)
            }) ?? true
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
        guard
            let clientID = bundle.object(
                forInfoDictionaryKey: "PistisGitHubClientID"
            ) as? String,
            let apiVersion = bundle.object(
                forInfoDictionaryKey: "PistisGitHubAPIVersion"
            ) as? String,
            let digestHex = bundle.object(
                forInfoDictionaryKey: "PistisGitHubAppConfigurationDigest"
            ) as? String,
            let digest = Data(hexadecimal: digestHex),
            let deviceCode = URL(string: "https://github.com/login/device/code"),
            let accessToken = URL(string: "https://github.com/login/oauth/access_token"),
            let authenticatedUser = URL(string: "https://api.github.com/user"),
            (try? GitHubEnrolmentConfiguration(
                clientID: clientID,
                deviceCodeEndpoint: deviceCode,
                accessTokenEndpoint: accessToken,
                authenticatedUserEndpoint: authenticatedUser,
                apiVersion: apiVersion,
                appConfigurationDigest: digest
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
                "Device Flow is implemented, but the verified provider-capability and Prosopikon receipt ports are absent."
            ),
            configurationLabel: "GitHub App public client configuration present",
            identityRule: "GitHub numeric account ID is the stable identity.",
            credentialRule: "No GitHub token or client secret is stored by Pistis."
        )
    }
}

extension Data {
    fileprivate init?(hexadecimal: String) {
        guard hexadecimal.utf8.count == 64,
            hexadecimal.utf8.allSatisfy({
                (0x30...0x39).contains($0)
                    || (0x61...0x66).contains($0)
                    || (0x41...0x46).contains($0)
            })
        else { return nil }
        var value = Data()
        value.reserveCapacity(32)
        var index = hexadecimal.startIndex
        while index < hexadecimal.endIndex {
            let end = hexadecimal.index(index, offsetBy: 2)
            guard let byte = UInt8(hexadecimal[index..<end], radix: 16) else {
                return nil
            }
            value.append(byte)
            index = end
        }
        self = value
    }
}
