import Foundation
import Testing
@testable import PistisCore

private let state = String(repeating: "s", count: 32)
private let verifier = String(repeating: "v", count: 43)

private func request() throws -> BrowserEnrolmentRequest {
    try BrowserEnrolmentRequest(
        provider: .github,
        authorizationURL: #require(URL(string: "https://github.com/login/oauth/authorize")),
        callbackURL: #require(URL(string: "pistis://oauth/callback")),
        state: state,
        pkceVerifier: verifier
    )
}

@Test func enrolmentAcceptsExactCallbackAndState() throws {
    let callback = try request().validateCallback(
        #require(URL(string: "pistis://oauth/callback?code=opaque-code&state=\(state)"))
    )
    #expect(callback == .authorizationCode("opaque-code"))
}

@Test func keeperAssistedFlowStillUsesGitHubSystemBrowserHost() throws {
    let enrolment = try request()
    #expect(enrolment.provider == .github)
    #expect(enrolment.authorizationURL.host == "github.com")
}

@Test func enrolmentRejectsLookalikeAuthorizationHost() throws {
    #expect(throws: BrowserEnrolmentError.invalidAuthorizationURL) {
        try BrowserEnrolmentRequest(
            provider: .github,
            authorizationURL: #require(URL(string: "https://github.com.attacker.example/oauth")),
            callbackURL: #require(URL(string: "pistis://oauth/callback")),
            state: state,
            pkceVerifier: verifier
        )
    }
}

@Test func enrolmentRejectsStateMismatchAndDuplicateCode() throws {
    let enrolment = try request()
    #expect(throws: BrowserEnrolmentError.stateMismatch) {
        try enrolment.validateCallback(
            #require(URL(string: "pistis://oauth/callback?code=x&state=wrong"))
        )
    }
    #expect(throws: BrowserEnrolmentError.malformedCallback) {
        try enrolment.validateCallback(
            #require(URL(string: "pistis://oauth/callback?code=x&code=y&state=\(state)"))
        )
    }
}

@Test func enrolmentRejectsWeakStateAndVerifier() throws {
    #expect(throws: BrowserEnrolmentError.invalidState) {
        try BrowserEnrolmentRequest(
            provider: .github,
            authorizationURL: #require(URL(string: "https://github.com/login/oauth/authorize")),
            callbackURL: #require(URL(string: "pistis://oauth/callback")),
            state: "short",
            pkceVerifier: verifier
        )
    }
    #expect(throws: BrowserEnrolmentError.invalidPKCEVerifier) {
        try BrowserEnrolmentRequest(
            provider: .github,
            authorizationURL: #require(URL(string: "https://github.com/login/oauth/authorize")),
            callbackURL: #require(URL(string: "pistis://oauth/callback")),
            state: state,
            pkceVerifier: "short"
        )
    }
}

@Test func providerErrorsAreRedacted() throws {
    let callback = try request().validateCallback(
        #require(URL(string: "pistis://oauth/callback?error=sensitive_internal_detail&state=\(state)"))
    )
    #expect(callback == .providerError("provider_error"))
}
