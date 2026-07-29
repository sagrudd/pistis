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
  private var attemptGeneration: UInt64 = 0
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
    let generatedAttemptID = try attemptIDGenerator.generate()
    guard generatedAttemptID.count == 16 else {
      throw GitHubDeviceFlowFailure.invalidConfiguration
    }
    guard attemptGeneration < UInt64.max else {
      throw GitHubDeviceFlowFailure.invalidConfiguration
    }
    attemptGeneration += 1
    let activeGeneration = attemptGeneration
    clearCapability()
    attemptID = generatedAttemptID
    phase = .requestingCode
    do {
      let authorization = try await client.requestDeviceAuthorization()
      try requireActiveAttempt(
        generatedAttemptID,
        generation: activeGeneration,
        phase: .requestingCode
      )
      let now = try await clock.nowNanoseconds()
      try requireActiveAttempt(
        generatedAttemptID,
        generation: activeGeneration,
        phase: .requestingCode
      )
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
      throw fail(
        with: normalized(error),
        for: generatedAttemptID,
        generation: activeGeneration
      )
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
      let activeAttemptID = attemptID,
      let capability,
      let expiryNanoseconds,
      var currentInterval = intervalSeconds
    else {
      throw GitHubDeviceFlowFailure.invalidLifecycle
    }
    let activeGeneration = attemptGeneration

    phase = .polling
    var polls = 0
    var transientRetries = 0
    var nextDelay = currentInterval
    var lastClockSample: UInt64?

    do {
      while polls < Self.maximumPolls {
        try Task.checkCancellation()
        lastClockSample = try await sleepBeforePoll(
          seconds: nextDelay,
          expiryNanoseconds: expiryNanoseconds,
          attemptID: activeAttemptID,
          generation: activeGeneration,
          notBefore: lastClockSample
        )
        polls += 1

        let pollStart = try await clock.nowNanoseconds()
        try requireActiveAttempt(
          activeAttemptID,
          generation: activeGeneration,
          phase: .polling
        )
        guard pollStart < expiryNanoseconds,
          lastClockSample.map({ pollStart >= $0 }) ?? true
        else {
          throw GitHubDeviceFlowFailure.attemptExpired
        }
        let result = try await client.poll(
          capability: capability,
          timeoutInterval: timeout(
            remainingNanoseconds: expiryNanoseconds - pollStart
          )
        )
        try requireActiveAttempt(
          activeAttemptID,
          generation: activeGeneration,
          phase: .polling
        )
        let afterPoll = try await clock.nowNanoseconds()
        try requireActiveAttempt(
          activeAttemptID,
          generation: activeGeneration,
          phase: .polling
        )
        guard afterPoll < expiryNanoseconds, afterPoll >= pollStart else {
          throw GitHubDeviceFlowFailure.attemptExpired
        }
        lastClockSample = afterPoll
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
          try requireActiveAttempt(
            activeAttemptID,
            generation: activeGeneration,
            phase: .identifying
          )
          guard identityStart < expiryNanoseconds,
            identityStart >= afterPoll
          else {
            throw GitHubDeviceFlowFailure.attemptExpired
          }
          let identity = try await client.authenticatedIdentity(
            using: token,
            timeoutInterval: timeout(
              remainingNanoseconds: expiryNanoseconds - identityStart
            )
          )
          try requireActiveAttempt(
            activeAttemptID,
            generation: activeGeneration,
            phase: .identifying
          )
          let afterIdentity = try await clock.nowNanoseconds()
          try requireActiveAttempt(
            activeAttemptID,
            generation: activeGeneration,
            phase: .identifying
          )
          guard afterIdentity < expiryNanoseconds,
            afterIdentity >= identityStart
          else {
            throw GitHubDeviceFlowFailure.attemptExpired
          }
          clearCapability()
          phase = .awaitingConfirmation(identity)
          return identity
        }
      }
      throw GitHubDeviceFlowFailure.tooManyPolls
    } catch {
      throw fail(
        with: normalized(error),
        for: activeAttemptID,
        generation: activeGeneration
      )
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
    expiryNanoseconds: UInt64,
    attemptID: Data,
    generation: UInt64,
    notBefore: UInt64?
  ) async throws -> UInt64 {
    let before = try await clock.nowNanoseconds()
    try requireActiveAttempt(
      attemptID,
      generation: generation,
      phase: .polling
    )
    guard before < expiryNanoseconds,
      notBefore.map({ before >= $0 }) ?? true,
      let delayNanoseconds = multiplyingSeconds(seconds),
      delayNanoseconds < expiryNanoseconds - before
    else {
      throw GitHubDeviceFlowFailure.attemptExpired
    }
    try await clock.sleep(nanoseconds: delayNanoseconds)
    try requireActiveAttempt(
      attemptID,
      generation: generation,
      phase: .polling
    )
    let after = try await clock.nowNanoseconds()
    try requireActiveAttempt(
      attemptID,
      generation: generation,
      phase: .polling
    )
    guard after < expiryNanoseconds, after >= before else {
      throw GitHubDeviceFlowFailure.attemptExpired
    }
    return after
  }

  private enum ActivePhase {
    case requestingCode
    case polling
    case identifying
  }

  private func requireActiveAttempt(
    _ expectedAttemptID: Data,
    generation expectedGeneration: UInt64,
    phase expectedPhase: ActivePhase
  ) throws {
    guard attemptID == expectedAttemptID,
      attemptGeneration == expectedGeneration
    else {
      throw GitHubDeviceFlowFailure.cancelled
    }
    let matchesPhase =
      switch (expectedPhase, phase) {
      case (.requestingCode, .requestingCode),
        (.polling, .polling),
        (.identifying, .identifying):
        true
      default:
        false
      }
    guard matchesPhase else {
      throw GitHubDeviceFlowFailure.cancelled
    }
  }

  private func fail(
    with failure: GitHubDeviceFlowFailure,
    for expectedAttemptID: Data,
    generation expectedGeneration: UInt64
  ) -> GitHubDeviceFlowFailure {
    guard attemptID == expectedAttemptID,
      attemptGeneration == expectedGeneration
    else {
      return .cancelled
    }
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
