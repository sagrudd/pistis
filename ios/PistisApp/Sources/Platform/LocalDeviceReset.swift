import Foundation

/// Every independent device-local store covered by the explicit Pistis reset.
///
/// The list is deliberately closed and regression-tested. Adding another
/// identity, installation or device-key store requires adding it here and to
/// the production operation list so reset cannot silently leave it behind.
enum LocalDeviceResetTarget: String, CaseIterable, Equatable {
  case installationTrust
  case secureEnclaveKeys
  case appAttestPrimaryReference
  case appAttestReplacementReference
  case firstAuthorityRecoveryEnvelope
  case siteRootConvergenceAcknowledgement
  case siteRootInstallationProjection
  case localHistory
  case onboardingEventJournal
}

struct LocalDeviceResetOperation {
  let target: LocalDeviceResetTarget
  let erase: @MainActor () async throws -> Void
}

struct LocalDeviceResetFailure: Error, Equatable {
  let failedTargets: [LocalDeviceResetTarget]
}

enum PistisOnboardingState {
  static let completedKey = "hasCompletedOnboarding"

  static func reset(defaults: UserDefaults = .standard) {
    defaults.set(false, forKey: completedKey)
  }
}

/// Coordinates one locally destructive reset without claiming server-side
/// revocation or deletion.
///
/// Face ID must succeed before any mutation. Once erasure begins, all closed
/// stores are attempted so one unavailable item cannot retain unrelated local
/// credentials. The onboarding-complete flag changes only after every target
/// succeeds; partial completion remains visibly in Settings and must not be
/// presented as a fresh device.
@MainActor
final class LocalDeviceResetService {
  static let shared = LocalDeviceResetService.production()

  private let authorize: @MainActor () async throws -> Void
  private let operations: [LocalDeviceResetOperation]
  private let markOnboardingIncomplete: @MainActor () -> Void

  init(
    authorize: @escaping @MainActor () async throws -> Void,
    operations: [LocalDeviceResetOperation],
    markOnboardingIncomplete: @escaping @MainActor () -> Void
  ) {
    self.authorize = authorize
    self.operations = operations
    self.markOnboardingIncomplete = markOnboardingIncomplete
  }

  var targets: [LocalDeviceResetTarget] {
    operations.map(\.target)
  }

  func reset() async throws {
    try await authorize()

    var failed: [LocalDeviceResetTarget] = []
    for operation in operations {
      do {
        try await operation.erase()
      } catch {
        failed.append(operation.target)
      }
    }
    guard failed.isEmpty else {
      throw LocalDeviceResetFailure(failedTargets: failed)
    }
    markOnboardingIncomplete()
  }

  private static func production() -> LocalDeviceResetService {
    LocalDeviceResetService(
      authorize: {
        _ = try await FaceIDCeremonyContext.authenticate(
          reason: "Reset all Pistis identities and installations on this iPhone"
        )
      },
      operations: [
        LocalDeviceResetOperation(target: .installationTrust) {
          try await InstallationTrustKeychain.shared.resetAllLocalEnrollments()
        },
        LocalDeviceResetOperation(target: .secureEnclaveKeys) {
          try SecureEnclaveSigner.resetAllApplicationKeys()
        },
        LocalDeviceResetOperation(target: .appAttestPrimaryReference) {
          try KeychainAppleAppAttestKeyIDStore().resetLocalReference()
        },
        LocalDeviceResetOperation(target: .appAttestReplacementReference) {
          try KeychainAppleAppAttestReplacementKeyStore().resetPendingReference()
        },
        LocalDeviceResetOperation(target: .firstAuthorityRecoveryEnvelope) {
          try KeychainFirstAuthorityRecoveryEnvelopeStore().resetLocalEnvelope()
        },
        LocalDeviceResetOperation(target: .siteRootConvergenceAcknowledgement) {
          try SiteRootConvergenceAckStoreV2().resetLocalRecord()
        },
        LocalDeviceResetOperation(target: .siteRootInstallationProjection) {
          SiteRootInstallationRepository.shared.resetAllLocalInstallations()
        },
        LocalDeviceResetOperation(target: .localHistory) {
          LocalHistoryRepository.shared.resetAllLocalHistory()
        },
        LocalDeviceResetOperation(target: .onboardingEventJournal) {
          OnboardingEventJournal.shared.resetAllLocalEvents()
        },
      ],
      markOnboardingIncomplete: {
        PistisOnboardingState.reset()
      }
    )
  }
}
