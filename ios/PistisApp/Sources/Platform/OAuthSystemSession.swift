import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(AuthenticationServices)
import AuthenticationServices
#endif
#if canImport(Security)
import Security
#endif

struct OAuthAttempt: Equatable, Sendable {
    let authorizationURL: URL
    let callbackURL: URL
    let state: String
    let codeVerifier: String
    let codeChallenge: String

    static func make(
        authorizationEndpoint: URL,
        clientID: String,
        callbackURL: URL,
        additionalItems: [URLQueryItem] = []
    ) throws -> OAuthAttempt {
        guard authorizationEndpoint.scheme == "https",
              !clientID.isEmpty,
              callbackURL.scheme != nil,
              callbackURL.host != nil,
              callbackURL.query == nil,
              callbackURL.fragment == nil
        else {
            throw PlatformFailure.invalidConfiguration
        }
        let reservedNames: Set<String> = [
            "client_id", "redirect_uri", "state", "code_challenge",
            "code_challenge_method",
        ]
        guard additionalItems.allSatisfy({ !reservedNames.contains($0.name) }) else {
            throw PlatformFailure.invalidConfiguration
        }
        let verifier = try OAuthRandom.base64URL(byteCount: 32)
        let state = try OAuthRandom.base64URL(byteCount: 32)
        let challenge = try PKCE.challenge(for: verifier)
        var components = URLComponents(
            url: authorizationEndpoint,
            resolvingAgainstBaseURL: false
        )
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: callbackURL.absoluteString),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ] + additionalItems
        guard let url = components?.url else {
            throw PlatformFailure.invalidConfiguration
        }
        return OAuthAttempt(
            authorizationURL: url,
            callbackURL: callbackURL,
            state: state,
            codeVerifier: verifier,
            codeChallenge: challenge
        )
    }

    func validate(callback: URL) throws -> OAuthAuthorizationCode {
        guard callback.scheme?.lowercased() == callbackURL.scheme?.lowercased(),
              callback.host?.lowercased() == callbackURL.host?.lowercased(),
              callback.port == callbackURL.port,
              callback.path == callbackURL.path,
              callback.fragment == nil,
              let components = URLComponents(url: callback, resolvingAgainstBaseURL: false)
        else {
            throw PlatformFailure.invalidOAuthCallback
        }
        let grouped = Dictionary(grouping: components.queryItems ?? [], by: \.name)
        guard grouped.values.allSatisfy({ $0.count == 1 }) else {
            throw PlatformFailure.invalidOAuthCallback
        }
        guard let returnedState = grouped["state"]?.first?.value,
              constantTimeEqual(returnedState, state)
        else {
            throw PlatformFailure.oauthStateMismatch
        }
        if grouped["error"] != nil {
            throw PlatformFailure.oauthDenied
        }
        guard let code = grouped["code"]?.first?.value,
              !code.isEmpty,
              code.utf8.count <= 1024
        else {
            throw PlatformFailure.invalidOAuthCallback
        }
        return OAuthAuthorizationCode(code: code, codeVerifier: codeVerifier)
    }
}

/// One-use material sent only to the trusted Pistis exchange broker.
struct OAuthAuthorizationCode: Equatable, Sendable {
    let code: String
    let codeVerifier: String
}

enum PKCE {
    static func challenge(for verifier: String) throws -> String {
        guard (43 ... 128).contains(verifier.utf8.count),
              verifier.unicodeScalars.allSatisfy({
                  $0.isASCII && (
                      CharacterSet.alphanumerics.contains($0)
                          || "-._~".unicodeScalars.contains($0)
                  )
              })
        else {
            throw PlatformFailure.invalidConfiguration
        }
        #if canImport(CryptoKit)
        return Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
        #else
        throw PlatformFailure.invalidConfiguration
        #endif
    }
}

private enum OAuthRandom {
    static func base64URL(byteCount: Int) throws -> String {
        #if canImport(Security)
        var bytes = [UInt8](repeating: 0, count: byteCount)
        guard SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes) == errSecSuccess else {
            throw PlatformFailure.randomnessUnavailable
        }
        return Data(bytes).base64URLEncodedString()
        #else
        throw PlatformFailure.randomnessUnavailable
        #endif
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private func constantTimeEqual(_ lhs: String, _ rhs: String) -> Bool {
    let left = Array(lhs.utf8)
    let right = Array(rhs.utf8)
    guard left.count == right.count else { return false }
    return zip(left, right).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
}

#if canImport(AuthenticationServices) && canImport(UIKit)
import UIKit

/// Runs provider enrolment in Apple's system authentication surface.
///
/// GitHub may ask iOS for a `github.com` passkey. If the person enabled Keeper
/// as their credential provider, iOS can offer it there. This adapter has no
/// Keeper API, vault access, passkey access, client secret, or provider token.
@MainActor
final class OAuthSystemSession: NSObject, ASWebAuthenticationPresentationContextProviding {
    private weak var presentationAnchor: UIWindow?
    private var session: ASWebAuthenticationSession?

    init(presentationAnchor: UIWindow) {
        self.presentationAnchor = presentationAnchor
    }

    func start(_ attempt: OAuthAttempt) async throws -> OAuthAuthorizationCode {
        guard session == nil else { throw PlatformFailure.invalidConfiguration }
        return try await withCheckedThrowingContinuation { continuation in
            let authenticationSession = ASWebAuthenticationSession(
                url: attempt.authorizationURL,
                callbackURLScheme: attempt.callbackURL.scheme
            ) { [weak self] callback, error in
                self?.session = nil
                if let authenticationError = error as? ASWebAuthenticationSessionError,
                   authenticationError.code == .canceledLogin
                {
                    continuation.resume(throwing: PlatformFailure.oauthDenied)
                    return
                }
                guard error == nil, let callback else {
                    continuation.resume(throwing: PlatformFailure.invalidOAuthCallback)
                    return
                }
                do {
                    continuation.resume(returning: try attempt.validate(callback: callback))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
            authenticationSession.presentationContextProvider = self
            // Preserve the person's normal system-browser credential context
            // so an enabled third-party passkey provider can participate.
            authenticationSession.prefersEphemeralWebBrowserSession = false
            session = authenticationSession
            guard authenticationSession.start() else {
                session = nil
                continuation.resume(throwing: PlatformFailure.invalidConfiguration)
                return
            }
        }
    }

    func cancel() {
        session?.cancel()
        session = nil
    }

    func presentationAnchor(
        for _: ASWebAuthenticationSession
    ) -> ASPresentationAnchor {
        presentationAnchor ?? ASPresentationAnchor()
    }
}
#endif
