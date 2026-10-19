import Foundation
import Harness
import Testing

@Test @MainActor func allBiometricFailuresStopBeforeEverySideEffect() async throws {
  let fixture = try EnrolledFixture()
  for biometric in BiometricOutcome.allCases where biometric != .success {
    var ledger = ModelledLedger()
    let report = await CeremonyRunner.run(
      qr: try fixture.qr(), fixture: fixture, biometric: biometric, ledger: &ledger
    )
    #expect(report.failure == "biometric_\(biometric.rawValue)")
    #expect(report.phase == "biometric")
    #expect(report.effects == SideEffects())
    #expect(report.biometricInput == biometric)
    #expect(report.biometricRequested)
  }
}

@Test @MainActor func explicitDenyIsSignedButDoesNotEstablishAModelledSession() async throws {
  let fixture = try EnrolledFixture()
  var ledger = ModelledLedger()
  let report = await CeremonyRunner.run(
    qr: try fixture.qr(), fixture: fixture, biometric: .success, denied: true, ledger: &ledger
  )
  #expect(report.outcome == "denied")
  #expect(report.effects.signatures == 1)
  #expect(report.effects.modelledSubmissions == 1)
  #expect(report.effects.modelledSessions == 0)
  #expect(report.effects.realNetworkRequests == 0)
}

@Test @MainActor func productionVerifierRejectsIndependentNegativeCases() async throws {
  let fixture = try EnrolledFixture()
  let cases: [(String, String)] = [
    (try fixture.qr(audience: "wrong-product"), "wrong_audience"),
    (try fixture.qr(installation: Data(repeating: 0x12, count: 16)), "unknown_installation"),
    (try fixture.qr(identity: Data(repeating: 0x45, count: 16)), "wrong_identity"),
    (try fixture.qr(expired: true), "expired"),
    (try fixture.qr(invalidSignature: true), "invalid_signature"),
    ("PISTIS1:invalid.0000000000000000", "invalid_checksum"),
    (String(repeating: "x", count: 2332), "oversized_frame"),
  ]
  for (qr, expectedFailure) in cases {
    var ledger = ModelledLedger()
    let report = await CeremonyRunner.run(
      qr: qr, fixture: fixture, biometric: .success, ledger: &ledger
    )
    #expect(report.phase == "qr_verification")
    #expect(report.failure == expectedFailure)
    #expect(report.effects == SideEffects())
    #expect(!report.biometricRequested)
  }
}

@Test @MainActor func unknownAndInactiveTrustCannotBeUpgradedByAScan() async throws {
  for enrolled in [true, false] {
    let fixture = try EnrolledFixture(active: false)
    var ledger = ModelledLedger()
    let report = await CeremonyRunner.run(
      qr: try fixture.qr(), fixture: fixture, biometric: .success,
      enrolled: enrolled, ledger: &ledger
    )
    #expect(report.failure == (enrolled ? "inactive_installation" : "unknown_installation"))
    #expect(report.effects == SideEffects())
  }
}

@Test @MainActor func cancellationDoesNotAuthoriseAFollowingCeremony() async throws {
  let fixture = try EnrolledFixture()
  var ledger = ModelledLedger()
  let qr = try fixture.qr()
  for outcome in [BiometricOutcome.success, .cancelled] {
    let report = await CeremonyRunner.run(
      qr: outcome == .success ? qr : try fixture.qr(challengeByte: 0x67),
      fixture: fixture, biometric: outcome, ledger: &ledger
    )
    if outcome == .cancelled {
      #expect(report.effects == SideEffects())
      #expect(report.failure == "biometric_cancelled")
    } else {
      #expect(report.effects.signatures == 1)
    }
  }
}

@Test @MainActor func modelledCheckpointRetainsReplayAndIdentityOwnership() async throws {
  let fixture = try EnrolledFixture()
  var ledger = ModelledLedger()
  let qr = try fixture.qr()
  let first = await CeremonyRunner.run(
    qr: qr, fixture: fixture, biometric: .success, ledger: &ledger)
  #expect(first.effects.modelledSessions == 1)
  var reopened = try JSONDecoder().decode(
    ModelledLedger.self, from: JSONEncoder().encode(ledger)
  )
  let replay = await CeremonyRunner.run(
    qr: qr, fixture: fixture, biometric: .success, ledger: &reopened)
  #expect(replay.failure == "replay")
  #expect(replay.effects == SideEffects())
  let replacement = try EnrolledFixture()
  let mismatch = await CeremonyRunner.run(
    qr: try replacement.qr(), fixture: replacement, biometric: .success, ledger: &reopened
  )
  #expect(mismatch.failure == "ledger_identity_mismatch")
  #expect(mismatch.effects == SideEffects())
}

@Test @MainActor func diagnosticsNeverIncludeFramesProofsOrIdentityPresentation() async throws {
  let fixture = try EnrolledFixture()
  var ledger = ModelledLedger()
  let qr = try fixture.qr()
  let report = await CeremonyRunner.run(
    qr: qr, fixture: fixture, biometric: .success, ledger: &ledger
  )
  let encoded = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
  for forbidden in [qr, "PISTIS1:", "fixture-user", "https://fixture.invalid", "authorityReceipt"] {
    #expect(!encoded.contains(forbidden))
  }
  #expect(!report.physicalDeviceEvidence)
  #expect(!report.genuineServiceReceipt)
  #expect(!report.releaseAcceptance)
}

@Test func structuralDecodeIsNotAuthentication() {
  #expect(inspectUntrustedQR("malformed").outcome == "failed")
}
