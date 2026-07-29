import Foundation
import Security

protocol GitHubDeviceFlowClock: Sendable {
    func nowNanoseconds() async throws -> UInt64
    func sleep(nanoseconds: UInt64) async throws
}

struct SystemGitHubDeviceFlowClock: GitHubDeviceFlowClock {
    func nowNanoseconds() async throws -> UInt64 {
        DispatchTime.now().uptimeNanoseconds
    }

    func sleep(nanoseconds: UInt64) async throws {
        try await Task.sleep(nanoseconds: nanoseconds)
    }
}

protocol GitHubAttemptIDGenerator: Sendable {
    func generate() throws -> Data
}

struct SecureGitHubAttemptIDGenerator: GitHubAttemptIDGenerator {
    func generate() throws -> Data {
        var bytes = Data(repeating: 0, count: 16)
        let status = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw GitHubDeviceFlowFailure.invalidConfiguration
        }
        return bytes
    }
}

enum GitHubDeviceFlowPhase: Equatable, Sendable {
    case idle
    case requestingCode
    case awaitingBrowser(GitHubDeviceAuthorizationPrompt)
    case browserSuspended(GitHubDeviceAuthorizationPrompt)
    case polling
    case identifying
    case awaitingConfirmation(GitHubStableIdentityProof)
    case cancelled
    case expired
    case failed(GitHubDeviceFlowFailure)
}

/// Owns one foreground GitHub Device Flow attempt through numeric-subject
/// retrieval. It deliberately stops before authority confirmation or storage.
actor GitHubDeviceFlowCoordinator {
    private static let maximumPolls = 90
    private static let maximumTransientRetries = 3
    private static let nanosecondsPerSecond: UInt64 = 1_000_000_000

    private let client: GitHubDeviceFlowClient
    private let clock: any GitHubDeviceFlowClock
    private let attemptIDGenerator: any GitHubAttemptIDGenerator
    private var attemptID: Data?
    private var capability: TransientGitHubSecret?
    private var expiryNanoseconds: UInt64?
    private var intervalSeconds: UInt64?
    private(set) var phase: GitHubDeviceFlowPhase = .idle

    init(
        client: GitHubDeviceFlowClient,
        clock: any GitHubDeviceFlowClock = SystemGitHubDeviceFlowClock(),
        attemptIDGenerator: any GitHubAttemptIDGenerator =
            SecureGitHubAttemptIDGenerator()
    ) {
        self.client = client
        self.clock = clock
        self.attemptIDGenerator = attemptIDGenerator
    }

    func start() async throws -> GitHubDeviceAuthorizationPrompt {
        guard phase == .idle || isTerminal else {
            throw GitHubDeviceFlowFailure.invalidLifecycle
        }
        clearCapability()
        phase = .requestingCode
        do {
            let generatedAttemptID = try attemptIDGenerator.generate()
            guard generatedAttemptID.count == 16 else {
                throw GitHubDeviceFlowFailure.invalidConfiguration
            }
            attemptID = generatedAttemptID
            let authorization = try await client.requestDeviceAuthorization()
            let now = try await clock.nowNanoseconds()
            guard
                let expiry = addingSeconds(
                    authorization.prompt.expiresInSeconds,
                    to: now
                )
            else {
                throw GitHubDeviceFlowFailure.invalidConfiguration
            }
            capability = authorization.capability
            expiryNanoseconds = expiry
            intervalSeconds = authorization.prompt.intervalSeconds
            phase = .awaitingBrowser(authorization.prompt)
            return authorization.prompt
        } catch {
            throw fail(with: normalized(error))
        }
    }

    /// Call only after the OS reports that Pistis opened the exact external
    /// verification URI. This is the sole permitted background suspension.
    func systemBrowserDidOpen() throws {
        guard case .awaitingBrowser(let prompt) = phase else {
            throw GitHubDeviceFlowFailure.invalidLifecycle
        }
        phase = .browserSuspended(prompt)
    }

    /// Returning to foreground never polls implicitly; an explicit user action
    /// invokes this method and waits at least the provider's initial interval.
    func resumeVerification() async throws -> GitHubStableIdentityProof {
        guard case .browserSuspended = phase,
            let capability,
            let expiryNanoseconds,
            var currentInterval = intervalSeconds
        else {
            throw GitHubDeviceFlowFailure.invalidLifecycle
        }

        phase = .polling
        var polls = 0
        var transientRetries = 0
        var nextDelay = currentInterval

        do {
            while polls < Self.maximumPolls {
                try Task.checkCancellation()
                try await sleepBeforePoll(
                    seconds: nextDelay,
                    expiryNanoseconds: expiryNanoseconds
                )
                polls += 1

                let pollStart = try await clock.nowNanoseconds()
                guard pollStart < expiryNanoseconds else {
                    throw GitHubDeviceFlowFailure.attemptExpired
                }
                let result = try await client.poll(
                    capability: capability,
                    timeoutInterval: timeout(
                        remainingNanoseconds: expiryNanoseconds - pollStart
                    )
                )
                guard try await clock.nowNanoseconds() < expiryNanoseconds else {
                    throw GitHubDeviceFlowFailure.attemptExpired
                }
                switch result {
                case .pending:
                    nextDelay = currentInterval
                case .slowDown:
                    guard currentInterval <= UInt64.max - 5 else {
                        throw GitHubDeviceFlowFailure.invalidConfiguration
                    }
                    currentInterval += 5
                    nextDelay = currentInterval
                case .transientFailure(let retryAfter):
                    guard transientRetries < Self.maximumTransientRetries else {
                        throw GitHubDeviceFlowFailure.retryExhausted
                    }
                    let backoffs: [UInt64] = [5, 10, 20]
                    nextDelay = max(
                        currentInterval,
                        backoffs[transientRetries],
                        retryAfter ?? 0
                    )
                    transientRetries += 1
                case .token(let token):
                    phase = .identifying
                    defer { token.clear() }
                    let identityStart = try await clock.nowNanoseconds()
                    guard identityStart < expiryNanoseconds else {
                        throw GitHubDeviceFlowFailure.attemptExpired
                    }
                    let identity = try await client.authenticatedIdentity(
                        using: token,
                        timeoutInterval: timeout(
                            remainingNanoseconds: expiryNanoseconds - identityStart
                        )
                    )
                    guard try await clock.nowNanoseconds() < expiryNanoseconds else {
                        throw GitHubDeviceFlowFailure.attemptExpired
                    }
                    clearCapability()
                    phase = .awaitingConfirmation(identity)
                    return identity
                }
            }
            throw GitHubDeviceFlowFailure.tooManyPolls
        } catch {
            throw fail(with: normalized(error))
        }
    }

    /// Any unrelated scene loss cancels. The owned browser suspension was
    /// already recorded by `systemBrowserDidOpen` and is the only exception.
    func applicationDidEnterBackground() {
        guard case .browserSuspended = phase else {
            cancel()
            return
        }
    }

    func memoryPressurePreventedProtectedRetention() {
        cancel()
    }

    func cancel() {
        clearCapability()
        phase = .cancelled
    }

    private func sleepBeforePoll(
        seconds: UInt64,
        expiryNanoseconds: UInt64
    ) async throws {
        let before = try await clock.nowNanoseconds()
        guard before < expiryNanoseconds,
            let delayNanoseconds = multiplyingSeconds(seconds),
            delayNanoseconds < expiryNanoseconds - before
        else {
            throw GitHubDeviceFlowFailure.attemptExpired
        }
        try await clock.sleep(nanoseconds: delayNanoseconds)
        let after = try await clock.nowNanoseconds()
        guard after < expiryNanoseconds, after >= before else {
            throw GitHubDeviceFlowFailure.attemptExpired
        }
    }

    private func fail(with failure: GitHubDeviceFlowFailure) -> GitHubDeviceFlowFailure {
        clearCapability()
        if failure == .attemptExpired || failure == .providerExpired {
            phase = .expired
        } else if failure == .cancelled {
            phase = .cancelled
        } else {
            phase = .failed(failure)
        }
        return failure
    }

    private func clearCapability() {
        capability?.clear()
        capability = nil
        attemptID = nil
        expiryNanoseconds = nil
        intervalSeconds = nil
    }

    private var isTerminal: Bool {
        switch phase {
        case .cancelled, .expired, .failed:
            true
        default:
            false
        }
    }

    private func normalized(_ error: Error) -> GitHubDeviceFlowFailure {
        if error is CancellationError { return .cancelled }
        return error as? GitHubDeviceFlowFailure ?? .transportUnavailable
    }

    private func addingSeconds(_ seconds: UInt64, to value: UInt64) -> UInt64? {
        guard let nanoseconds = multiplyingSeconds(seconds),
            value <= UInt64.max - nanoseconds
        else { return nil }
        return value + nanoseconds
    }

    private func multiplyingSeconds(_ seconds: UInt64) -> UInt64? {
        guard seconds <= UInt64.max / Self.nanosecondsPerSecond else { return nil }
        return seconds * Self.nanosecondsPerSecond
    }

    private func timeout(remainingNanoseconds: UInt64) throws -> TimeInterval {
        let value = min(
            10,
            TimeInterval(remainingNanoseconds) / TimeInterval(Self.nanosecondsPerSecond)
        )
        guard value > 0 else {
            throw GitHubDeviceFlowFailure.attemptExpired
        }
        return value
    }
}
