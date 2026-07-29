import Foundation

enum GitHubDeviceFlowFailure: Error, Equatable, Sendable {
    case invalidConfiguration
    case invalidLifecycle
    case malformedResponse
    case providerDenied
    case providerExpired
    case providerRejected
    case retryExhausted
    case attemptExpired
    case tooManyPolls
    case transportUnavailable
    case cancelled
}

struct GitHubHTTPResponse: Sendable {
    let statusCode: Int
    let headers: [String: String]
    let body: Data
    let finalURL: URL

    func header(named name: String) -> String? {
        headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value
    }
}

protocol GitHubDeviceFlowTransport: Sendable {
    func perform(_ request: URLRequest) async throws -> GitHubHTTPResponse
}

private final class GitHubURLTaskCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var task: URLSessionTask?

    func install(_ task: URLSessionTask) {
        lock.withLock {
            self.task = task
            if Task.isCancelled {
                task.cancel()
            }
        }
    }

    func cancel() {
        lock.withLock {
            task?.cancel()
        }
    }
}

final class URLSessionGitHubDeviceFlowTransport:
    NSObject, GitHubDeviceFlowTransport, URLSessionDataDelegate, @unchecked Sendable
{
    private struct PendingRequest {
        let maximumBytes: Int
        let continuation: CheckedContinuation<GitHubHTTPResponse, Error>
        var response: URLResponse?
        var body = Data()
    }

    private let lock = NSLock()
    private var pending: [Int: PendingRequest] = [:]
    private let configuration: URLSessionConfiguration

    init(configuration: URLSessionConfiguration = .ephemeral) {
        self.configuration = configuration
        super.init()
    }

    private lazy var session: URLSession = {
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 10
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }()

    func perform(_ request: URLRequest) async throws -> GitHubHTTPResponse {
        guard let url = request.url else {
            throw GitHubDeviceFlowFailure.invalidConfiguration
        }
        let maximumBytes =
            url == URL(string: "https://api.github.com/user")
            ? GitHubDeviceFlowClient.maximumUserResponseBytes
            : GitHubDeviceFlowClient.maximumDeviceResponseBytes
        let cancellation = GitHubURLTaskCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let task = session.dataTask(with: request)
                lock.withLock {
                    pending[task.taskIdentifier] = PendingRequest(
                        maximumBytes: maximumBytes,
                        continuation: continuation
                    )
                }
                cancellation.install(task)
                task.resume()
            }
        } onCancel: {
            cancellation.cancel()
        }
    }

    func urlSession(
        _: URLSession,
        task _: URLSessionTask,
        willPerformHTTPRedirection _: HTTPURLResponse,
        newRequest _: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    func urlSession(
        _: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        let oversized = lock.withLock {
            guard var request = pending[dataTask.taskIdentifier] else { return true }
            if response.expectedContentLength > Int64(request.maximumBytes) {
                return true
            }
            request.response = response
            pending[dataTask.taskIdentifier] = request
            return false
        }
        if oversized {
            finish(
                taskIdentifier: dataTask.taskIdentifier,
                result: .failure(GitHubDeviceFlowFailure.malformedResponse)
            )
            completionHandler(.cancel)
        } else {
            completionHandler(.allow)
        }
    }

    func urlSession(
        _: URLSession,
        dataTask: URLSessionDataTask,
        didReceive data: Data
    ) {
        let exceeded = lock.withLock {
            guard var request = pending[dataTask.taskIdentifier] else { return true }
            guard data.count <= request.maximumBytes - request.body.count else {
                return true
            }
            request.body.append(data)
            pending[dataTask.taskIdentifier] = request
            return false
        }
        if exceeded {
            dataTask.cancel()
            finish(
                taskIdentifier: dataTask.taskIdentifier,
                result: .failure(GitHubDeviceFlowFailure.malformedResponse)
            )
        }
    }

    func urlSession(
        _: URLSession,
        task: URLSessionTask,
        didCompleteWithError error: Error?
    ) {
        let request = lock.withLock {
            pending.removeValue(forKey: task.taskIdentifier)
        }
        guard let request else { return }
        if let error {
            let nsError = error as NSError
            request.continuation.resume(
                throwing: nsError.domain == NSURLErrorDomain
                    && nsError.code == NSURLErrorCancelled
                    ? GitHubDeviceFlowFailure.cancelled
                    : GitHubDeviceFlowFailure.transportUnavailable
            )
            return
        }
        guard let http = request.response as? HTTPURLResponse,
            let finalURL = http.url
        else {
            request.continuation.resume(
                throwing: GitHubDeviceFlowFailure.transportUnavailable
            )
            return
        }
        request.continuation.resume(
            returning: GitHubHTTPResponse(
                statusCode: http.statusCode,
                headers: http.allHeaderFields.reduce(into: [:]) { result, item in
                    guard let key = item.key as? String,
                        let value = item.value as? String
                    else { return }
                    result[key] = value
                },
                body: request.body,
                finalURL: finalURL
            )
        )
    }

    private func finish(
        taskIdentifier: Int,
        result: Result<GitHubHTTPResponse, Error>
    ) {
        let continuation = lock.withLock {
            pending.removeValue(forKey: taskIdentifier)?.continuation
        }
        continuation?.resume(with: result)
    }
}

/// Public values shown before opening GitHub's external verification page.
struct GitHubDeviceAuthorizationPrompt: Equatable, Sendable {
    let userCode: String
    let verificationURI: URL
    let expiresInSeconds: UInt64
    let intervalSeconds: UInt64
}

/// Process-memory-only device-flow capability. It is deliberately a reference
/// so all users share the same best-effort clearing operation.
final class TransientGitHubSecret: @unchecked Sendable, CustomStringConvertible {
    private let lock = NSLock()
    private var bytes: Data

    init(bytes: Data) {
        self.bytes = bytes
    }

    var description: String { "<redacted GitHub capability>" }

    func withASCIIString<T>(_ operation: (String) throws -> T) throws -> T {
        try lock.withLock {
            guard !bytes.isEmpty, let value = String(data: bytes, encoding: .ascii) else {
                throw GitHubDeviceFlowFailure.cancelled
            }
            return try operation(value)
        }
    }

    func clear() {
        lock.withLock {
            bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex)
            bytes.removeAll(keepingCapacity: false)
        }
    }

    deinit {
        clear()
    }
}

struct GitHubDeviceAuthorization: Sendable {
    let prompt: GitHubDeviceAuthorizationPrompt
    let capability: TransientGitHubSecret
}

enum GitHubTokenPollResult: Sendable {
    case pending
    case slowDown
    case transientFailure(retryAfterSeconds: UInt64?)
    case token(TransientGitHubSecret)
}

struct GitHubDeviceFlowClient: Sendable {
    static let maximumDeviceResponseBytes = 4_096
    static let maximumTokenErrorBytes = 1_024
    static let maximumUserResponseBytes = 65_536

    private let configuration: GitHubEnrolmentConfiguration
    private let transport: any GitHubDeviceFlowTransport
    private let userAgent: String

    init(
        configuration: GitHubEnrolmentConfiguration,
        transport: any GitHubDeviceFlowTransport,
        userAgent: String = "Pistis-iOS/0.1"
    ) throws {
        guard (1...64).contains(userAgent.utf8.count),
            userAgent.unicodeScalars.allSatisfy({
                $0.isASCII && !CharacterSet.controlCharacters.contains($0)
            })
        else {
            throw GitHubDeviceFlowFailure.invalidConfiguration
        }
        self.configuration = configuration
        self.transport = transport
        self.userAgent = userAgent
    }

    func requestDeviceAuthorization() async throws -> GitHubDeviceAuthorization {
        var request = baseRequest(url: configuration.deviceCodeEndpoint, method: "POST")
        request.setValue(
            "application/x-www-form-urlencoded; charset=utf-8",
            forHTTPHeaderField: "Content-Type"
        )
        request.httpBody = Data(
            "client_id=\(formEncode(configuration.clientID))".utf8
        )
        let response = try await perform(request, expectedURL: configuration.deviceCodeEndpoint)
        guard response.statusCode == 200,
            validJSONContentType(response),
            response.body.count <= Self.maximumDeviceResponseBytes
        else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        let object = try StrictJSONObject(
            data: response.body,
            maximumBytes: Self.maximumDeviceResponseBytes
        ).values
        guard
            Set(object.keys) == [
                "device_code", "user_code", "verification_uri", "expires_in", "interval",
            ],
            case .string(let deviceCode)? = object["device_code"],
            deviceCode.utf8.count == 40,
            deviceCode.unicodeScalars.allSatisfy(\.isASCII),
            case .string(let userCode)? = object["user_code"],
            isUserCode(userCode),
            case .string(let verificationURI)? = object["verification_uri"],
            verificationURI == GitHubEnrolmentConfiguration.verificationURI.absoluteString,
            case .number(let expiresLexeme)? = object["expires_in"],
            let expires = boundedUnsigned(expiresLexeme, range: 1...900),
            case .number(let intervalLexeme)? = object["interval"],
            let interval = boundedUnsigned(intervalLexeme, range: 1...60)
        else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        return GitHubDeviceAuthorization(
            prompt: .init(
                userCode: userCode,
                verificationURI: GitHubEnrolmentConfiguration.verificationURI,
                expiresInSeconds: expires,
                intervalSeconds: interval
            ),
            capability: TransientGitHubSecret(bytes: Data(deviceCode.utf8))
        )
    }

    func poll(
        capability: TransientGitHubSecret,
        timeoutInterval: TimeInterval = 10
    ) async throws -> GitHubTokenPollResult {
        guard timeoutInterval > 0, timeoutInterval <= 10 else {
            throw GitHubDeviceFlowFailure.invalidConfiguration
        }
        var request = baseRequest(url: configuration.accessTokenEndpoint, method: "POST")
        request.timeoutInterval = timeoutInterval
        request.setValue(
            "application/x-www-form-urlencoded; charset=utf-8",
            forHTTPHeaderField: "Content-Type"
        )
        request.httpBody = try capability.withASCIIString { deviceCode in
            Data(
                ("client_id=\(formEncode(configuration.clientID))"
                    + "&device_code=\(formEncode(deviceCode))"
                    + "&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code").utf8
            )
        }
        let response: GitHubHTTPResponse
        do {
            response = try await perform(request, expectedURL: configuration.accessTokenEndpoint)
        } catch is CancellationError {
            throw GitHubDeviceFlowFailure.cancelled
        } catch let failure as GitHubDeviceFlowFailure {
            if failure == .transportUnavailable {
                return .transientFailure(retryAfterSeconds: nil)
            }
            throw failure
        } catch {
            return .transientFailure(retryAfterSeconds: nil)
        }
        if response.statusCode == 429 || response.statusCode == 503 {
            return .transientFailure(
                retryAfterSeconds: try retryAfter(from: response)
            )
        }
        if (500...599).contains(response.statusCode) {
            return .transientFailure(
                retryAfterSeconds: try retryAfter(from: response)
            )
        }
        guard response.statusCode == 200, validJSONContentType(response) else {
            throw GitHubDeviceFlowFailure.providerRejected
        }
        if response.body.count <= Self.maximumTokenErrorBytes,
            let error = try? decodeError(response.body)
        {
            switch error {
            case "authorization_pending":
                return .pending
            case "slow_down":
                return .slowDown
            case "expired_token":
                throw GitHubDeviceFlowFailure.providerExpired
            case "access_denied":
                throw GitHubDeviceFlowFailure.providerDenied
            default:
                throw GitHubDeviceFlowFailure.providerRejected
            }
        }
        return .token(try decodeToken(response.body))
    }

    func authenticatedIdentity(
        using token: TransientGitHubSecret,
        timeoutInterval: TimeInterval = 10
    ) async throws -> GitHubStableIdentityProof {
        guard timeoutInterval > 0, timeoutInterval <= 10 else {
            throw GitHubDeviceFlowFailure.invalidConfiguration
        }
        var request = baseRequest(
            url: configuration.authenticatedUserEndpoint,
            method: "GET"
        )
        request.timeoutInterval = timeoutInterval
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue(
            configuration.apiVersion,
            forHTTPHeaderField: "X-GitHub-Api-Version"
        )
        request.setValue(
            try token.withASCIIString { "Bearer \($0)" },
            forHTTPHeaderField: "Authorization"
        )
        let response = try await perform(
            request,
            expectedURL: configuration.authenticatedUserEndpoint
        )
        guard response.statusCode == 200,
            validJSONContentType(response),
            response.body.count <= Self.maximumUserResponseBytes
        else {
            throw GitHubDeviceFlowFailure.providerRejected
        }
        let object = try StrictJSONObject(
            data: response.body,
            maximumBytes: Self.maximumUserResponseBytes
        ).values
        guard case .number(let subjectLexeme)? = object["id"],
            let subject = canonicalSubject(subjectLexeme)
        else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        let login = try boundedDisplay(object["login"], required: false, maximumBytes: 128)
        _ = try boundedDisplay(object["name"], required: false, maximumBytes: 256)
        _ = try boundedDisplay(object["email"], required: false, maximumBytes: 320)
        _ = try boundedDisplay(object["html_url"], required: false, maximumBytes: 2_048)
        return try GitHubStableIdentityProof(
            numericSubject: subject,
            displayLogin: login
        )
    }

    private func baseRequest(url: URL, method: String) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = 10
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        return request
    }

    private func perform(
        _ request: URLRequest,
        expectedURL: URL
    ) async throws -> GitHubHTTPResponse {
        do {
            let response = try await transport.perform(request)
            guard response.finalURL == expectedURL else {
                throw GitHubDeviceFlowFailure.providerRejected
            }
            return response
        } catch is CancellationError {
            throw GitHubDeviceFlowFailure.cancelled
        } catch let failure as GitHubDeviceFlowFailure {
            throw failure
        } catch {
            throw GitHubDeviceFlowFailure.transportUnavailable
        }
    }

    private func validJSONContentType(_ response: GitHubHTTPResponse) -> Bool {
        guard let raw = response.header(named: "Content-Type") else { return false }
        let normalized = raw.lowercased().replacingOccurrences(of: " ", with: "")
        return normalized == "application/json"
            || normalized == "application/json;charset=utf-8"
    }

    private func decodeToken(_ data: Data) throws -> TransientGitHubSecret {
        let object = try StrictJSONObject(
            data: data,
            maximumBytes: Self.maximumDeviceResponseBytes
        ).values
        let expiringKeys = Set([
            "access_token", "token_type", "scope",
            "expires_in", "refresh_token", "refresh_token_expires_in",
        ])
        guard Set(object.keys) == expiringKeys,
            case .string(let accessToken)? = object["access_token"],
            isPrintableASCII(accessToken, range: 1...4_096),
            case .string(let tokenType)? = object["token_type"],
            tokenType == "bearer",
            case .string(let scope)? = object["scope"],
            scope.isEmpty
        else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        guard case .number(let expires)? = object["expires_in"],
            boundedUnsigned(expires, range: 1...UInt64.max) != nil,
            case .string(let refreshToken)? = object["refresh_token"],
            isPrintableASCII(refreshToken, range: 1...4_096),
            case .number(let refreshExpires)? = object["refresh_token_expires_in"],
            boundedUnsigned(refreshExpires, range: 1...UInt64.max) != nil
        else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        // Refresh credentials are intentionally never returned or retained.
        return TransientGitHubSecret(bytes: Data(accessToken.utf8))
    }

    private func decodeError(_ data: Data) throws -> String {
        let object = try StrictJSONObject(
            data: data,
            maximumBytes: Self.maximumTokenErrorBytes
        ).values
        let allowed = Set(["error", "error_description", "error_uri"])
        guard !object.keys.isEmpty, Set(object.keys).isSubset(of: allowed),
            case .string(let error)? = object["error"],
            isPrintableASCII(error, range: 1...128)
        else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        for key in ["error_description", "error_uri"] {
            if let value = object[key] {
                guard case .string(let text) = value,
                    isPrintableASCII(text, range: 1...1_024)
                else {
                    throw GitHubDeviceFlowFailure.malformedResponse
                }
            }
        }
        return error
    }

    private func retryAfter(from response: GitHubHTTPResponse) throws -> UInt64? {
        guard let raw = response.header(named: "Retry-After") else { return nil }
        guard let value = boundedUnsigned(raw, range: 0...900) else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        return value
    }

    private func boundedDisplay(
        _ value: StrictJSONObject.Value?,
        required: Bool,
        maximumBytes: Int
    ) throws -> String? {
        guard let value else {
            if required { throw GitHubDeviceFlowFailure.malformedResponse }
            return nil
        }
        if case .null = value, !required { return nil }
        guard case .string(let text) = value,
            !text.isEmpty,
            text.utf8.count <= maximumBytes,
            !text.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
        else {
            throw GitHubDeviceFlowFailure.malformedResponse
        }
        return text
    }

    private func canonicalSubject(_ lexeme: String) -> UInt64? {
        guard !lexeme.isEmpty, lexeme.utf8.count <= 20,
            lexeme.utf8.allSatisfy({ (0x30...0x39).contains($0) }),
            lexeme.first != "0",
            lexeme.utf8.count < 20 || lexeme <= "18446744073709551615"
        else { return nil }
        return UInt64(lexeme)
    }

    private func boundedUnsigned(
        _ lexeme: String,
        range: ClosedRange<UInt64>
    ) -> UInt64? {
        guard !lexeme.isEmpty,
            lexeme.utf8.allSatisfy({ (0x30...0x39).contains($0) }),
            lexeme == "0" || lexeme.first != "0",
            let value = UInt64(lexeme),
            range.contains(value)
        else { return nil }
        return value
    }

    private func isUserCode(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        return bytes.count == 9 && bytes[4] == 0x2d
            && bytes.enumerated().allSatisfy { index, byte in
                index == 4 || (0x30...0x39).contains(byte) || (0x41...0x5a).contains(byte)
            }
    }

    private func isPrintableASCII(
        _ value: String,
        range: ClosedRange<Int>
    ) -> Bool {
        range.contains(value.utf8.count)
            && value.utf8.allSatisfy { (0x21...0x7e).contains($0) }
    }

    private func formEncode(_ value: String) -> String {
        value.utf8.map { byte in
            if (0x41...0x5a).contains(byte) || (0x61...0x7a).contains(byte)
                || (0x30...0x39).contains(byte) || [0x2d, 0x2e, 0x5f, 0x7e].contains(byte)
            {
                return String(UnicodeScalar(byte))
            }
            return String(format: "%%%02X", byte)
        }.joined()
    }
}
