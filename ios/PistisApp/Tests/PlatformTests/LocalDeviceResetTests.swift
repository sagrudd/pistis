import Foundation
import XCTest

@testable import Pistis

@MainActor
final class LocalDeviceResetTests: XCTestCase {
  private enum FixtureFailure: Error {
    case denied
    case erase
  }

  func testFaceIDFailurePreventsEveryMutation() async {
    var erased: [LocalDeviceResetTarget] = []
    var completed = false
    let service = LocalDeviceResetService(
      authorize: { throw FixtureFailure.denied },
      operations: [
        LocalDeviceResetOperation(target: .installationTrust) {
          erased.append(.installationTrust)
        }
      ],
      markOnboardingIncomplete: { completed = true }
    )

    do {
      try await service.reset()
      XCTFail("reset unexpectedly succeeded")
    } catch {
      XCTAssertTrue(error is FixtureFailure)
    }
    XCTAssertEqual(erased, [])
    XCTAssertFalse(completed)
  }

  func testSuccessfulResetErasesEveryTargetBeforeReturningToOnboarding() async throws {
    var events: [String] = []
    let operations = LocalDeviceResetTarget.allCases.map { target in
      LocalDeviceResetOperation(target: target) {
        events.append("erase:\(target.rawValue)")
      }
    }
    let service = LocalDeviceResetService(
      authorize: { events.append("authorize") },
      operations: operations,
      markOnboardingIncomplete: { events.append("onboarding") }
    )

    try await service.reset()

    XCTAssertEqual(events.first, "authorize")
    XCTAssertEqual(events.last, "onboarding")
    XCTAssertEqual(
      Array(events.dropFirst().dropLast()),
      LocalDeviceResetTarget.allCases.map { "erase:\($0.rawValue)" }
    )
  }

  func testPartialFailureAttemptsRemainingStoresAndDoesNotPresentFreshDevice() async {
    var erased: [LocalDeviceResetTarget] = []
    var completed = false
    let service = LocalDeviceResetService(
      authorize: {},
      operations: LocalDeviceResetTarget.allCases.map { target in
        LocalDeviceResetOperation(target: target) {
          erased.append(target)
          if target == .secureEnclaveKeys
            || target == .firstAuthorityRecoveryEnvelope
          {
            throw FixtureFailure.erase
          }
        }
      },
      markOnboardingIncomplete: { completed = true }
    )

    do {
      try await service.reset()
      XCTFail("partial reset unexpectedly succeeded")
    } catch let failure as LocalDeviceResetFailure {
      XCTAssertEqual(
        failure.failedTargets,
        [.secureEnclaveKeys, .firstAuthorityRecoveryEnvelope]
      )
    } catch {
      XCTFail("unexpected reset failure: \(error)")
    }
    XCTAssertEqual(erased, LocalDeviceResetTarget.allCases)
    XCTAssertFalse(completed)
  }

  func testCompletionStateRemainsResetAcrossRelaunch() async throws {
    let suite = "LocalDeviceResetTests.\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    defaults.set(true, forKey: PistisOnboardingState.completedKey)
    let service = LocalDeviceResetService(
      authorize: {},
      operations: [],
      markOnboardingIncomplete: { PistisOnboardingState.reset(defaults: defaults) }
    )

    try await service.reset()

    XCTAssertFalse(defaults.bool(forKey: PistisOnboardingState.completedKey))
    let relaunched = try XCTUnwrap(UserDefaults(suiteName: suite))
    XCTAssertFalse(relaunched.bool(forKey: PistisOnboardingState.completedKey))
  }

  func testAboutPresentsExactVersionAndBuild() {
    XCTAssertEqual(
      PistisBuildIdentity.display(infoDictionary: [
        "CFBundleShortVersionString": "0.23.0",
        "CFBundleVersion": "47",
      ]),
      "0.23.0 (47)"
    )
    XCTAssertEqual(PistisBuildIdentity.display(infoDictionary: [:]), "Unknown build")
  }

  func testUserDefaultsProjectionsAreCompletelyErased() throws {
    let suite = "LocalDeviceResetTests.\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let installations = SiteRootInstallationRepository(defaults: defaults)
    let history = LocalHistoryRepository(defaults: defaults)
    let journal = OnboardingEventJournal(defaults: defaults, nowUnixMillis: { 1_000 })

    try installations.recordRecoveredFirstCeremony(
      authorityHost: "monas.example.test",
      redactedReference: "ceremony-1",
      registeredAt: Date(timeIntervalSince1970: 1)
    )
    try history.record(
      HistoryEvent(
        id: UUID(), action: "fixture", installation: "fixture",
        occurredAt: "now", decision: "none", signature: "none",
        transfer: "none", verification: "none"
      )
    )
    try journal.append(
      try OnboardingEvent(
        id: UUID(), attemptID: UUID(), flow: .firstDeviceSiteRoot,
        kind: .completed, stage: .proofResponse, outcome: .succeeded,
        httpStatus: 200, authority: .fixedInstallBroker,
        occurredAtUnixMillis: 1_000
      )
    )

    installations.resetAllLocalInstallations()
    history.resetAllLocalHistory()
    journal.resetAllLocalEvents()

    XCTAssertEqual(try installations.records(), [])
    XCTAssertEqual(try history.records(), [])
    XCTAssertEqual(try journal.events(), [])
  }

  #if canImport(LocalAuthentication) && canImport(Security)
    func testSecureEnclaveResetSelectsOnlyExactPistisTagPrefix() {
      let first = Data("org.mnemosyne.pistis.device-key.installation-1".utf8)
      let second = Data("org.mnemosyne.pistis.device-key.site-root-delegation-v1".utf8)
      let foreign = Data("org.example.device-key.installation-1".utf8)
      let nearMiss = Data("org.mnemosyne.pistis.device-keys.installation-1".utf8)

      XCTAssertEqual(
        SecureEnclaveSigner.ownedApplicationTags(
          [foreign, second, first, nearMiss, second]
        ),
        [first, second]
      )
    }
  #endif
}
