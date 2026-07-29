import Foundation
import XCTest

@testable import Pistis

final class GitHubDeviceFlowTests: XCTestCase {
    func testExactDeviceRequestAndStrictPrompt() async throws {
        let transport = ScriptedGitHubTransport([
            success(
                url: endpoint("https://github.com/login/device/code"),
                json: deviceAuthorizationJSON()
            )
        ])
        let client = try makeClient(transport: transport)
        let authorization = try await client.requestDeviceAuthorization()

        XCTAssertEqual(authorization.prompt.userCode, "ABCD-1234")
        XCTAssertEqual(
            authorization.prompt.verificationURI.absoluteString,
            "https://github.com/login/device"
        )
        let requests = await transport.requests
        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(requests[0].httpMethod, "POST")
        XCTAssertEqual(
            requests[0].url?.absoluteString,
            "https://github.com/login/device/code"
        )
        XCTAssertEqual(
            requests[0].value(forHTTPHeaderField: "Content-Type"),
            "application/x-www-form-urlencoded; charset=utf-8"
        )
        XCTAssertEqual(
            String(data: try XCTUnwrap(requests[0].httpBody), encoding: .utf8),
            "client_id=Iv23lievHWZTGyot0BXa"
        )
        XCTAssertFalse(
            try XCTUnwrap(String(data: requests[0].httpBody!, encoding: .utf8))
                .contains("scope")
        )
        XCTAssertEqual(authorization.capability.description, "<redacted GitHub capability>")
    }

    func testPendingSlowDownTokenAndNumericSubject() async throws {
        let transport = ScriptedGitHubTransport([
            success(
                url: endpoint("https://github.com/login/device/code"),
                json: deviceAuthorizationJSON(expires: 120, interval: 5)
            ),
            success(
                url: endpoint("https://github.com/login/oauth/access_token"),
                json: #"{"error":"authorization_pending"}"#
            ),
            success(
                url: endpoint("https://github.com/login/oauth/access_token"),
                json: #"{"error":"slow_down"}"#
            ),
            success(
                url: endpoint("https://github.com/login/oauth/access_token"),
                json: tokenJSON()
            ),
            success(
                url: endpoint("https://api.github.com/user"),
                json:
                    #"{"id":18446744073709551615,"login":"synthetic-user","name":null,"email":null,"html_url":"https://github.com/synthetic-user"}"#
            ),
        ])
        let clock = AdvancingGitHubClock()
        let coordinator = try GitHubDeviceFlowCoordinator(
            client: makeClient(transport: transport),
            clock: clock,
            attemptIDGenerator: FixedGitHubAttemptIDGenerator()
        )

        _ = try await coordinator.start()
        try await coordinator.systemBrowserDidOpen()
        let proof = try await coordinator.resumeVerification()

        XCTAssertEqual(proof.numericSubject, UInt64.max)
        XCTAssertEqual(proof.displayLogin, "synthetic-user")
        let completedPhase = await coordinator.phase
        let completedSleeps = await clock.sleeps
        XCTAssertEqual(completedPhase, .awaitingConfirmation(proof))
        XCTAssertEqual(
            completedSleeps,
            [5, 5, 10].map { UInt64($0) * 1_000_000_000 }
        )

        let requests = await transport.requests
        XCTAssertEqual(requests.count, 5)
        for request in requests[1...3] {
            XCTAssertEqual(
                request.url?.absoluteString,
                "https://github.com/login/oauth/access_token"
            )
            XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
        }
        XCTAssertEqual(
            requests[4].value(forHTTPHeaderField: "Authorization"),
            "Bearer synthetic-access-token"
        )
        XCTAssertEqual(
            requests[4].value(forHTTPHeaderField: "X-GitHub-Api-Version"),
            "2022-11-28"
        )
        XCTAssertEqual(
            requests[4].value(forHTTPHeaderField: "Accept"),
            "application/vnd.github+json"
        )
    }

    func testRetryAfterOnlyIncreasesBoundedRetryDelay() async throws {
        let transport = ScriptedGitHubTransport([
            success(
                url: endpoint("https://github.com/login/device/code"),
                json: deviceAuthorizationJSON(expires: 120, interval: 2)
            ),
            response(
                url: endpoint("https://github.com/login/oauth/access_token"),
                status: 503,
                headers: ["Retry-After": "7"],
                body: Data()
            ),
            success(
                url: endpoint("https://github.com/login/oauth/access_token"),
                json: tokenJSON()
            ),
            success(
                url: endpoint("https://api.github.com/user"),
                json: #"{"id":3848500,"login":"sagrudd"}"#
            ),
        ])
        let clock = AdvancingGitHubClock()
        let coordinator = try GitHubDeviceFlowCoordinator(
            client: makeClient(transport: transport),
            clock: clock,
            attemptIDGenerator: FixedGitHubAttemptIDGenerator()
        )
        _ = try await coordinator.start()
        try await coordinator.systemBrowserDidOpen()
        _ = try await coordinator.resumeVerification()
        let retrySleeps = await clock.sleeps
        XCTAssertEqual(
            retrySleeps,
            [2, 7].map { UInt64($0) * 1_000_000_000 }
        )
    }

    func testExpiryStopsBeforeFirstPoll() async throws {
        let transport = ScriptedGitHubTransport([
            success(
                url: endpoint("https://github.com/login/device/code"),
                json: deviceAuthorizationJSON(expires: 5, interval: 5)
            )
        ])
        let coordinator = try GitHubDeviceFlowCoordinator(
            client: makeClient(transport: transport),
            clock: AdvancingGitHubClock(),
            attemptIDGenerator: FixedGitHubAttemptIDGenerator()
        )
        _ = try await coordinator.start()
        try await coordinator.systemBrowserDidOpen()
        do {
            _ = try await coordinator.resumeVerification()
            XCTFail("expired attempt polled")
        } catch {
            XCTAssertEqual(error as? GitHubDeviceFlowFailure, .attemptExpired)
        }
        let expiredPhase = await coordinator.phase
        let requestCount = await transport.requests.count
        XCTAssertEqual(expiredPhase, .expired)
        XCTAssertEqual(requestCount, 1)
    }

    func testFourthTransientFailureExhaustsThreeRetries() async throws {
        let tokenURL = endpoint("https://github.com/login/oauth/access_token")
        let transport = ScriptedGitHubTransport([
            success(
                url: endpoint("https://github.com/login/device/code"),
                json: deviceAuthorizationJSON(expires: 120, interval: 2)
            ),
            response(url: tokenURL, status: 500, headers: [:], body: Data()),
            response(url: tokenURL, status: 500, headers: [:], body: Data()),
            response(url: tokenURL, status: 500, headers: [:], body: Data()),
            response(url: tokenURL, status: 500, headers: [:], body: Data()),
        ])
        let clock = AdvancingGitHubClock()
        let coordinator = try GitHubDeviceFlowCoordinator(
            client: makeClient(transport: transport),
            clock: clock,
            attemptIDGenerator: FixedGitHubAttemptIDGenerator()
        )
        _ = try await coordinator.start()
        try await coordinator.systemBrowserDidOpen()
        do {
            _ = try await coordinator.resumeVerification()
            XCTFail("retry exhaustion accepted")
        } catch {
            XCTAssertEqual(error as? GitHubDeviceFlowFailure, .retryExhausted)
        }
        let sleeps = await clock.sleeps
        XCTAssertEqual(
            sleeps,
            [2, 5, 10, 20].map { UInt64($0) * 1_000_000_000 }
        )
    }

    func testBackgroundOutsideOwnedBrowserCancelsAndClearsCapability() async throws {
        let transport = ScriptedGitHubTransport([
            success(
                url: endpoint("https://github.com/login/device/code"),
                json: deviceAuthorizationJSON()
            )
        ])
        let coordinator = try GitHubDeviceFlowCoordinator(
            client: makeClient(transport: transport),
            clock: AdvancingGitHubClock(),
            attemptIDGenerator: FixedGitHubAttemptIDGenerator()
        )
        _ = try await coordinator.start()
        await coordinator.applicationDidEnterBackground()
        let cancelledPhase = await coordinator.phase
        XCTAssertEqual(cancelledPhase, .cancelled)
        do {
            _ = try await coordinator.resumeVerification()
            XCTFail("cancelled flow resumed")
        } catch {
            XCTAssertEqual(error as? GitHubDeviceFlowFailure, .invalidLifecycle)
        }
    }

    func testOwnedBrowserRequiresExplicitResume() async throws {
        let transport = ScriptedGitHubTransport([
            success(
                url: endpoint("https://github.com/login/device/code"),
                json: deviceAuthorizationJSON()
            )
        ])
        let coordinator = try GitHubDeviceFlowCoordinator(
            client: makeClient(transport: transport),
            clock: AdvancingGitHubClock(),
            attemptIDGenerator: FixedGitHubAttemptIDGenerator()
        )
        let prompt = try await coordinator.start()
        try await coordinator.systemBrowserDidOpen()
        await coordinator.applicationDidEnterBackground()
        let suspendedPhase = await coordinator.phase
        let requestCount = await transport.requests.count
        XCTAssertEqual(suspendedPhase, .browserSuspended(prompt))
        XCTAssertEqual(requestCount, 1)
    }

    func testMalformedAndSubstitutedProviderResponsesFailClosed() async throws {
        let invalidDeviceResponses = [
            #"{"device_code":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","device_code":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}"#,
            #"{"device_code":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","user_code":"ABCD-1234","verification_uri":"https://attacker.test/device","expires_in":900,"interval":5}"#,
            #"{"device_code":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","user_code":"abcd-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}"#,
            #"{"device_code":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":901,"interval":5}"#,
            #"{"device_code":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5,"extra":true}"#,
        ]
        for json in invalidDeviceResponses {
            let transport = ScriptedGitHubTransport([
                success(
                    url: endpoint("https://github.com/login/device/code"),
                    json: json
                )
            ])
            do {
                _ = try await makeClient(transport: transport).requestDeviceAuthorization()
                XCTFail("invalid device response accepted: \(json)")
            } catch {
                XCTAssertEqual(error as? GitHubDeviceFlowFailure, .malformedResponse)
            }
        }
    }

    func testNumericSubjectRejectsRoundedStringSignedAndLeadingZeroForms() async throws {
        let invalidSubjects = [
            #""3848500""#,
            #"-1"#,
            #"03848500"#,
            #"3.8485e6"#,
            #"18446744073709551616"#,
            #"0"#,
        ]
        for subject in invalidSubjects {
            let transport = ScriptedGitHubTransport([
                success(
                    url: endpoint("https://api.github.com/user"),
                    json: #"{"id":\#(subject),"login":"synthetic-user"}"#
                )
            ])
            let token = TransientGitHubSecret(bytes: Data("token".utf8))
            do {
                _ = try await makeClient(transport: transport)
                    .authenticatedIdentity(using: token)
                XCTFail("invalid subject accepted: \(subject)")
            } catch {
                XCTAssertEqual(error as? GitHubDeviceFlowFailure, .malformedResponse)
            }
            token.clear()
        }
    }

    func testAuthenticatedUserIgnoresBoundedUnrelatedProviderFields() async throws {
        let transport = ScriptedGitHubTransport([
            success(
                url: endpoint("https://api.github.com/user"),
                json:
                    #"{"id":3848500,"login":null,"avatar_url":"https://avatars.example/user","site_admin":false,"plan":{"name":"free","collaborators":0},"organizations_url":"https://api.github.com/user/orgs"}"#
            )
        ])
        let token = TransientGitHubSecret(bytes: Data("token".utf8))
        defer { token.clear() }
        let proof = try await makeClient(transport: transport)
            .authenticatedIdentity(using: token)
        XCTAssertEqual(proof.numericSubject, 3_848_500)
        XCTAssertNil(proof.displayLogin)
    }

    func testUnknownErrorAndInvalidRetryAfterAreTerminal() async throws {
        let errorTransport = ScriptedGitHubTransport([
            success(
                url: endpoint("https://github.com/login/oauth/access_token"),
                json: #"{"error":"token_expired"}"#
            )
        ])
        do {
            _ = try await makeClient(transport: errorTransport).poll(
                capability: TransientGitHubSecret(bytes: Data(repeating: 0x61, count: 40))
            )
            XCTFail("unknown token_expired error accepted")
        } catch {
            XCTAssertEqual(error as? GitHubDeviceFlowFailure, .providerRejected)
        }

        let retryTransport = ScriptedGitHubTransport([
            response(
                url: endpoint("https://github.com/login/oauth/access_token"),
                status: 503,
                headers: ["Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"],
                body: Data()
            )
        ])
        do {
            _ = try await makeClient(transport: retryTransport).poll(
                capability: TransientGitHubSecret(bytes: Data(repeating: 0x61, count: 40))
            )
            XCTFail("date-form Retry-After accepted")
        } catch {
            XCTAssertEqual(error as? GitHubDeviceFlowFailure, .malformedResponse)
        }
    }

    func testTransientSecretClearsAndNeverDescribesItsValue() throws {
        let secret = TransientGitHubSecret(bytes: Data("sensitive-value".utf8))
        XCTAssertFalse(secret.description.contains("sensitive-value"))
        secret.clear()
        XCTAssertThrowsError(try secret.withASCIIString { $0 })
    }

    func testProductionTransportCancelsOversizeBodyDuringDownload() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [OversizedGitHubURLProtocol.self]
        let transport = URLSessionGitHubDeviceFlowTransport(
            configuration: configuration
        )
        do {
            _ = try await transport.perform(
                URLRequest(url: endpoint("https://github.com/login/device/code"))
            )
            XCTFail("oversize body was buffered")
        } catch {
            XCTAssertEqual(error as? GitHubDeviceFlowFailure, .malformedResponse)
        }
    }
}

private actor ScriptedGitHubTransport: GitHubDeviceFlowTransport {
    private var responses: [GitHubHTTPResponse]
    private(set) var requests: [URLRequest] = []

    init(_ responses: [GitHubHTTPResponse]) {
        self.responses = responses
    }

    func perform(_ request: URLRequest) async throws -> GitHubHTTPResponse {
        requests.append(request)
        guard !responses.isEmpty else {
            throw GitHubDeviceFlowFailure.transportUnavailable
        }
        return responses.removeFirst()
    }
}

private actor AdvancingGitHubClock: GitHubDeviceFlowClock {
    private var now: UInt64 = 1_000_000
    private(set) var sleeps: [UInt64] = []

    func nowNanoseconds() async throws -> UInt64 {
        now
    }

    func sleep(nanoseconds: UInt64) async throws {
        sleeps.append(nanoseconds)
        now += nanoseconds
    }
}

private struct FixedGitHubAttemptIDGenerator: GitHubAttemptIDGenerator {
    func generate() throws -> Data {
        Data(repeating: 0x11, count: 16)
    }
}

private final class OversizedGitHubURLProtocol: URLProtocol, @unchecked Sendable {
    override class func canInit(with _: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: 200,
            httpVersion: "HTTP/1.1",
            headerFields: [
                "Content-Type": "application/json",
                "Content-Length": "5000",
            ]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(repeating: 0x61, count: 5_000))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private func makeClient(
    transport: any GitHubDeviceFlowTransport
) throws -> GitHubDeviceFlowClient {
    try GitHubDeviceFlowClient(
        configuration: GitHubEnrolmentConfiguration(
            clientID: GitHubEnrolmentConfiguration.reviewedClientID,
            deviceCodeEndpoint: endpoint("https://github.com/login/device/code"),
            accessTokenEndpoint: endpoint("https://github.com/login/oauth/access_token"),
            authenticatedUserEndpoint: endpoint("https://api.github.com/user"),
            apiVersion: "2022-11-28",
            appConfigurationDigest: Data(repeating: 0x55, count: 32)
        ),
        transport: transport
    )
}

private func endpoint(_ value: String) -> URL {
    URL(string: value)!
}

private func success(url: URL, json: String) -> GitHubHTTPResponse {
    response(
        url: url,
        status: 200,
        headers: ["Content-Type": "application/json; charset=utf-8"],
        body: Data(json.utf8)
    )
}

private func response(
    url: URL,
    status: Int,
    headers: [String: String],
    body: Data
) -> GitHubHTTPResponse {
    GitHubHTTPResponse(
        statusCode: status,
        headers: headers,
        body: body,
        finalURL: url
    )
}

private func deviceAuthorizationJSON(
    expires: UInt64 = 900,
    interval: UInt64 = 5
) -> String {
    #"{"device_code":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":\#(expires),"interval":\#(interval)}"#
}

private func tokenJSON() -> String {
    #"{"access_token":"synthetic-access-token","token_type":"bearer","scope":"","expires_in":28800,"refresh_token":"synthetic-discarded-refresh","refresh_token_expires_in":15811200}"#
}
