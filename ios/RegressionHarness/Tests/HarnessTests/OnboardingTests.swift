import Foundation
import Harness
import Testing

@Test @MainActor func firstDevicePNGUsesProductionPresentationBindingAndReceipt() throws {
  let fixture = try OnboardingFixture()
  let executable = fixtureRoundtripExecutable()
  let acquired = try roundtripFixtureImage(fixture.qr, executable: executable)
  var state = ModelledOnboardingState()
  let report = OnboardingRunner.run(
    qr: acquired, fixture: fixture, biometric: .success, state: &state)
  #expect(report.outcome == "modelled_enrolled")
  #expect(report.modelledTrustCommits == 1)
  #expect(report.effects.signatures == 1)
  #expect(report.effects.modelledSubmissions == 1)
  #expect(report.effects.modelledSessions == 0)
  #expect(report.effects.realNetworkRequests == 0)
  #expect(report.effects.privateKeyWrites == 0)
}

@Test @MainActor func onboardingBiometricFailuresHaveNoSignatureOrRetainedTrust() throws {
  let fixture = try OnboardingFixture()
  for biometric in BiometricOutcome.allCases where biometric != .success {
    var state = ModelledOnboardingState()
    let report = OnboardingRunner.run(
      qr: fixture.qr, fixture: fixture, biometric: biometric, state: &state)
    #expect(report.failure == "biometric_\(biometric.rawValue)")
    #expect(report.effects == SideEffects())
    #expect(report.modelledTrustCommits == 0)
    #expect(try state.snapshot() == nil)
  }
}

@Test @MainActor func everyReceiptAndTransportFaultPreventsTrustCommit() throws {
  let fixture = try OnboardingFixture()
  for fault in OnboardingFault.allCases where fault != .none {
    var state = ModelledOnboardingState()
    let report = OnboardingRunner.run(
      qr: fixture.qr, fixture: fixture, biometric: .success, state: &state, fault: fault)
    #expect(report.outcome != "modelled_enrolled")
    #expect(report.failure != nil)
    #expect(report.modelledTrustCommits == 0)
    #expect(report.effects.modelledSessions == 0)
    #expect(report.effects.realNetworkRequests == 0)
    let snapshot = try #require(try state.snapshot())
    var reopened = try ModelledOnboardingState.restore(snapshot, fixture: fixture)
    let retry = OnboardingRunner.run(
      qr: fixture.qr, fixture: fixture, biometric: .success, state: &reopened)
    #expect(retry.outcome == "modelled_enrolled")
    #expect(retry.effects.signatures == 0)
    #expect(retry.modelledTrustCommits == 1)
  }
}

@Test @MainActor func interruptedSnapshotAndDuplicateDoNotResignOrRecommit() throws {
  let fixture = try OnboardingFixture()
  var state = ModelledOnboardingState()
  let interrupted = OnboardingRunner.run(
    qr: fixture.qr, fixture: fixture, biometric: .success, state: &state,
    fault: .interruptedAfterRegistration)
  #expect(interrupted.effects.signatures == 1)
  #expect(interrupted.effects.modelledSubmissions == 0)
  let snapshot = try #require(try state.snapshot())
  var reopened = try ModelledOnboardingState.restore(snapshot, fixture: fixture)
  let denied = OnboardingRunner.run(
    qr: fixture.qr, fixture: fixture, biometric: .cancelled, state: &reopened)
  #expect(denied.effects == SideEffects())
  #expect(try reopened.snapshot() == snapshot)
  let resumed = OnboardingRunner.run(
    qr: fixture.qr, fixture: fixture, biometric: .success, state: &reopened)
  #expect(resumed.effects.signatures == 0)
  #expect(resumed.modelledTrustCommits == 1)
  var committed = try ModelledOnboardingState.restore(
    try #require(try reopened.snapshot()), fixture: fixture)
  let duplicate = OnboardingRunner.run(
    qr: fixture.qr, fixture: fixture, biometric: .success, state: &committed)
  #expect(duplicate.outcome == "modelled_enrolled")
  #expect(duplicate.effects == SideEffects())
  #expect(duplicate.modelledTrustCommits == 0)
  #expect(!duplicate.biometricRequested)
}

@Test @MainActor func malformedLegacyForeignAndExpiredSnapshotsCannotRestoreTrust() throws {
  let fixture = try OnboardingFixture()
  var state = ModelledOnboardingState()
  _ = OnboardingRunner.run(qr: fixture.qr, fixture: fixture, biometric: .success, state: &state)
  let snapshot = try #require(try state.snapshot())
  for bytes in [
    Data(), Data("{}".utf8), Data(snapshot.dropLast()), Data(repeating: 0, count: 8193),
  ] {
    #expect(throws: (any Error).self) {
      try ModelledOnboardingState.restore(bytes, fixture: fixture)
    }
  }
  #expect(throws: (any Error).self) {
    try ModelledOnboardingState.restore(snapshot, fixture: OnboardingFixture())
  }
  #expect(throws: (any Error).self) {
    try ModelledOnboardingState.restore(
      snapshot, fixture: fixture, now: OnboardingFixture.now.addingTimeInterval(195))
  }
  var object = try #require(JSONSerialization.jsonObject(with: snapshot) as? [String: Any])
  object["active"] = true
  let extra = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  #expect(throws: (any Error).self) {
    try ModelledOnboardingState.restore(extra, fixture: fixture)
  }
  object.removeValue(forKey: "active")
  object["registration"] = Data([0]).base64EncodedString()
  let corrupt = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  #expect(throws: (any Error).self) {
    try ModelledOnboardingState.restore(corrupt, fixture: fixture)
  }
}

@Test @MainActor func presentationAndConfigurationFailuresPrecedeBiometricsAndSigning() throws {
  let fixture = try OnboardingFixture()
  for (qr, digest, now, failure) in [
    (fixture.qr, Data(repeating: 0, count: 32), OnboardingFixture.now, "wrong_configuration"),
    (
      fixture.qr, fixture.configurationDigest, OnboardingFixture.now.addingTimeInterval(300),
      "expired_presentation"
    ),
    (
      fixture.qr + "\n", fixture.configurationDigest, OnboardingFixture.now,
      "malformed_presentation"
    ),
  ] {
    var state = ModelledOnboardingState()
    let report = OnboardingRunner.run(
      qr: qr, fixture: fixture, biometric: .success, state: &state,
      configurationDigest: digest, now: now)
    #expect(report.failure == failure)
    #expect(report.effects == SideEffects())
    #expect(report.modelledTrustCommits == 0)
    #expect(!report.biometricRequested)
    #expect(try state.snapshot() == nil)
  }
}

@Test @MainActor func onboardingDiagnosticsNeverExposeQRProofOrPrivateKey() throws {
  let fixture = try OnboardingFixture()
  var state = ModelledOnboardingState()
  let report = OnboardingRunner.run(
    qr: fixture.qr, fixture: fixture, biometric: .success, state: &state)
  let data = try JSONEncoder().encode(report)
  let text = try #require(String(data: data, encoding: .utf8))
  #expect(!text.contains(fixture.qr))
  #expect(text.contains("\"genuineServiceReceipt\":false"))
  #expect(text.contains("\"physicalDeviceEvidence\":false"))
  #expect(text.contains("\"releaseAcceptance\":false"))
}

@Test @MainActor func challengeDeadlineRejectsFreshAndPendingBeforeAnyNewEffect() throws {
  let fixture = try OnboardingFixture()
  for elapsed in [139.999, 140, 145] {
    for pending in [false, true] {
      var state = ModelledOnboardingState()
      if pending {
        _ = OnboardingRunner.run(
          qr: fixture.qr, fixture: fixture, biometric: .success, state: &state,
          fault: .interruptedAfterRegistration)
        state = try ModelledOnboardingState.restore(
          try #require(try state.snapshot()), fixture: fixture)
      }
      let before = try state.snapshot()
      let report = OnboardingRunner.run(
        qr: fixture.qr, fixture: fixture, biometric: .success, state: &state,
        now: OnboardingFixture.now.addingTimeInterval(elapsed))
      if elapsed < 140 {
        #expect(report.outcome == "modelled_enrolled")
        #expect(report.effects.signatures == (pending ? 0 : 1))
        #expect(report.modelledTrustCommits == 1)
      } else {
        #expect(report.failure == "expired_authority_challenge")
        #expect(report.phase == "authority_challenge_verification")
        #expect(report.effects == SideEffects())
        #expect(report.modelledTrustCommits == 0)
        #expect(!report.biometricRequested)
        #expect(try state.snapshot() == before)
      }
    }
  }
}

@Test @MainActor func expiredChallengeDoesNotInvalidateIntactCommittedReceipt() throws {
  let fixture = try OnboardingFixture()
  var state = ModelledOnboardingState()
  _ = OnboardingRunner.run(qr: fixture.qr, fixture: fixture, biometric: .success, state: &state)
  let snapshot = try #require(try state.snapshot())
  var restored = try ModelledOnboardingState.restore(
    snapshot, fixture: fixture, now: OnboardingFixture.now.addingTimeInterval(145))
  let duplicate = OnboardingRunner.run(
    qr: fixture.qr, fixture: fixture, biometric: .rejected, state: &restored,
    now: OnboardingFixture.now.addingTimeInterval(145))
  #expect(duplicate.outcome == "modelled_enrolled")
  #expect(duplicate.effects == SideEffects())
  #expect(duplicate.modelledTrustCommits == 0)
  #expect(!duplicate.biometricRequested)
  #expect(try restored.snapshot() == snapshot)
}

@Test @MainActor func canonicalCheckpointDoesNotProveRollbackIntegrity() throws {
  let fixture = try OnboardingFixture()
  var state = ModelledOnboardingState()
  _ = OnboardingRunner.run(qr: fixture.qr, fixture: fixture, biometric: .success, state: &state)
  let snapshot = try #require(try state.snapshot())
  var object = try #require(JSONSerialization.jsonObject(with: snapshot) as? [String: Any])
  object["receipt"] = Data([0]).base64EncodedString()
  let corrupt = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  #expect(throws: (any Error).self) {
    try ModelledOnboardingState.restore(corrupt, fixture: fixture)
  }
  object.removeValue(forKey: "receipt")
  let rolledBack = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  var pending = try ModelledOnboardingState.restore(rolledBack, fixture: fixture)
  let retry = OnboardingRunner.run(
    qr: fixture.qr, fixture: fixture, biometric: .success, state: &pending)
  #expect(retry.outcome == "modelled_enrolled")
  #expect(retry.effects.signatures == 0)
  #expect(retry.effects.modelledSubmissions == 1)
  #expect(retry.modelledTrustCommits == 1)
  #expect(!retry.checkpointRollbackProtection)
}
