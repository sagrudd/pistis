import Foundation

/// Non-secret public-client configuration for accepted GitHub enrolment.
struct GitHubEnrolmentConfiguration: Equatable, Sendable {
    static let reviewedClientID = "Iv23lievHWZTGyot0BXa"
    static let reviewedAppConfigurationDigest = Data([
        0xbf, 0x79, 0x68, 0x03, 0x0a, 0xbd, 0xf7, 0xd3,
        0xda, 0xbb, 0x38, 0x9f, 0x32, 0xcd, 0x4c, 0x53,
        0x10, 0xc1, 0xec, 0x4c, 0x9c, 0x62, 0x5d, 0x38,
        0xd1, 0x3b, 0xe6, 0xef, 0xae, 0x23, 0x06, 0x63,
    ])
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
            appConfigurationDigest == Self.reviewedAppConfigurationDigest
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
        guard configuration(bundle: bundle) != nil else {
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
            state: .ready,
            configurationLabel: "GitHub App public client configuration verified",
            identityRule: "GitHub numeric account ID is the stable identity.",
            credentialRule: "Provider credentials remain transient and are cleared after verification."
        )
    }

    static func configuration(bundle: Bundle = .main)
        -> GitHubEnrolmentConfiguration?
    {
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
            let configuration = try? GitHubEnrolmentConfiguration(
                clientID: clientID,
                deviceCodeEndpoint: deviceCode,
                accessTokenEndpoint: accessToken,
                authenticatedUserEndpoint: authenticatedUser,
                apiVersion: apiVersion,
                appConfigurationDigest: digest
            )
        else { return nil }
        return configuration
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
