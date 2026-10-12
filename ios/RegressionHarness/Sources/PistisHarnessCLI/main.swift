import Foundation
import Harness

@main
struct PistisHarnessCLI {
  @MainActor
  static func main() async {
    var arguments = Array(CommandLine.arguments.dropFirst())
    var imageRoundtrip: URL?
    if arguments.count == 3,
      ["self-test", "self-test-onboarding"].contains(arguments[0]),
      arguments[1] == "--qr-roundtrip"
    {
      imageRoundtrip = URL(fileURLWithPath: arguments[2])
      arguments = [arguments[0]]
    }
    switch arguments {
    case ["inspect"]:
      do {
        let text = try readBoundedText()
        let report = inspectUntrustedQR(text)
        printJSON(report)
        exit(report.outcome == "blocked" ? 2 : 1)
      } catch {
        printJSON(Diagnostic(outcome: "failed", phase: "qr_acquisition", failure: "invalid_input"))
        exit(1)
      }
    case ["self-test-onboarding"]:
      guard let imageRoundtrip else {
        printJSON(OnboardingDiagnostic())
        exit(1)
      }
      do {
        let fixture = try OnboardingFixture()
        let acquired = try roundtripFixtureImage(fixture.qr, executable: imageRoundtrip)
        var observations: [OnboardingObservation] = []
        for biometric in BiometricOutcome.allCases {
          var state = ModelledOnboardingState()
          let report = OnboardingRunner.run(
            qr: acquired, fixture: fixture, biometric: biometric, state: &state)
          let correct =
            biometric == .success
            ? report.outcome == "modelled_enrolled" && report.modelledTrustCommits == 1
            : report.phase == "biometric" && report.effects == SideEffects()
              && report.modelledTrustCommits == 0
          observations.append(
            OnboardingObservation(
              scenario: "face_id_\(biometric.rawValue)", expectationMet: correct, diagnostic: report
            ))
        }
        for fault in OnboardingFault.allCases where fault != .none {
          var state = ModelledOnboardingState()
          let report = OnboardingRunner.run(
            qr: acquired, fixture: fixture, biometric: .success, state: &state, fault: fault)
          observations.append(
            OnboardingObservation(
              scenario: fault.rawValue,
              expectationMet: report.outcome != "modelled_enrolled" && report.failure != nil
                && report.modelledTrustCommits == 0 && report.effects.modelledSessions == 0,
              diagnostic: report))
          let snapshot = try state.snapshot()
          guard let snapshot else { throw InputFailure.invalid }
          var reopened = try ModelledOnboardingState.restore(snapshot, fixture: fixture)
          let retry = OnboardingRunner.run(
            qr: acquired, fixture: fixture, biometric: .success, state: &reopened)
          observations.append(
            OnboardingObservation(
              scenario: "retry_after_\(fault.rawValue)",
              expectationMet: retry.outcome == "modelled_enrolled" && retry.effects.signatures == 0
                && retry.modelledTrustCommits == 1,
              diagnostic: retry))
          let duplicate = OnboardingRunner.run(
            qr: acquired, fixture: fixture, biometric: .success, state: &reopened)
          observations.append(
            OnboardingObservation(
              scenario: "duplicate_after_\(fault.rawValue)",
              expectationMet: duplicate.outcome == "modelled_enrolled"
                && duplicate.effects == SideEffects() && duplicate.modelledTrustCommits == 0,
              diagnostic: duplicate))
        }
        for pending in [false, true] {
          var state = ModelledOnboardingState()
          if pending {
            _ = OnboardingRunner.run(
              qr: acquired, fixture: fixture, biometric: .success, state: &state,
              fault: .interruptedAfterRegistration)
          }
          let snapshot = try state.snapshot()
          let stale = OnboardingRunner.run(
            qr: acquired, fixture: fixture, biometric: .success, state: &state,
            now: OnboardingFixture.now.addingTimeInterval(140))
          let unchanged = try state.snapshot() == snapshot
          observations.append(
            OnboardingObservation(
              scenario: pending ? "expired_pending_challenge" : "expired_fresh_challenge",
              expectationMet: stale.failure == "expired_authority_challenge"
                && stale.effects == SideEffects() && stale.modelledTrustCommits == 0
                && !stale.biometricRequested && unchanged,
              diagnostic: stale))
        }
        let suite = OnboardingSuite(
          expectationsMet: observations.allSatisfy(\.expectationMet), observations: observations)
        printJSON(suite)
        if !suite.expectationsMet { exit(1) }
      } catch {
        var report = OnboardingDiagnostic()
        report.phase = "fixture_or_image_acquisition"
        report.failure = "onboarding_self_test_failed"
        printJSON(report)
        exit(1)
      }
    case ["self-test"]:
      do {
        let fixture = try EnrolledFixture()
        var observations: [Observation] = []
        for biometric in BiometricOutcome.allCases {
          var ledger = ModelledLedger()
          let original = try fixture.qr()
          let acquired =
            try imageRoundtrip.map {
              try roundtripFixtureImage(original, executable: $0)
            } ?? original
          let report = await CeremonyRunner.run(
            qr: acquired, fixture: fixture, biometric: biometric, ledger: &ledger
          )
          let success = biometric == .success
          let correct =
            success
            ? report.outcome == "modelled_session" && report.effects.signatures == 1
            : report.phase == "biometric" && report.effects == SideEffects()
          observations.append(
            Observation(
              scenario: "face_id_\(biometric.rawValue)",
              acquisition: imageRoundtrip == nil ? "bounded_text" : "png_roundtrip",
              expectationMet: correct, diagnostic: report
            ))
        }
        var ledger = ModelledLedger()
        let denied = await CeremonyRunner.run(
          qr: try fixture.qr(), fixture: fixture, biometric: .success, denied: true, ledger: &ledger
        )
        observations.append(
          Observation(
            scenario: "explicit_signed_deny",
            acquisition: "bounded_text",
            expectationMet: denied.outcome == "denied"
              && denied.effects.signatures == 1 && denied.effects.modelledSessions == 0,
            diagnostic: denied
          ))
        let replay = await CeremonyRunner.run(
          qr: try fixture.qr(), fixture: fixture, biometric: .success, ledger: &ledger
        )
        observations.append(
          Observation(
            scenario: "replay_after_deny",
            acquisition: "bounded_text",
            expectationMet: replay.failure == "replay" && replay.effects == SideEffects(),
            diagnostic: replay
          ))
        let suite = Suite(
          expectationsMet: observations.allSatisfy(\.expectationMet), observations: observations
        )
        printJSON(suite)
        if !suite.expectationsMet { exit(1) }
      } catch {
        printJSON(
          Diagnostic(
            outcome: "failed", phase: "fixture_generation", failure: "fixture_generation_failed"
          ))
        exit(1)
      }
    default:
      printJSON(Diagnostic(outcome: "failed", phase: "arguments", failure: "invalid_arguments"))
      exit(1)
    }
  }

  private static func readBoundedText() throws -> String {
    let maximum = 2331
    var data = Data()
    while data.count <= maximum {
      guard let chunk = try FileHandle.standardInput.read(upToCount: maximum + 1 - data.count),
        !chunk.isEmpty
      else { break }
      data.append(chunk)
    }
    guard data.count <= maximum, let text = String(data: data, encoding: .utf8) else {
      throw InputFailure.invalid
    }
    return text
  }

  private static func printJSON<T: Encodable>(_ value: T) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    guard let data = try? encoder.encode(value), let text = String(data: data, encoding: .utf8)
    else {
      print("{\"outcome\":\"failed\",\"failure\":\"diagnostic_encoding_failed\"}")
      exit(1)
    }
    print(text)
  }
}

private enum InputFailure: Error { case invalid }

private struct Observation: Encodable {
  let scenario: String
  let acquisition: String
  let expectationMet: Bool
  let diagnostic: Diagnostic
}

private struct Suite: Encodable {
  let schema = "synoptikon.pistis-harness.suite.v1"
  let expectationsMet: Bool
  let observations: [Observation]
  let milestoneComplete = false
}

private struct OnboardingObservation: Encodable {
  let scenario: String
  let expectationMet: Bool
  let diagnostic: OnboardingDiagnostic
}

private struct OnboardingSuite: Encodable {
  let schema = "synoptikon.pistis-onboarding.suite.v1"
  let acquisition = "png_roundtrip"
  let expectationsMet: Bool
  let observations: [OnboardingObservation]
  let milestoneComplete = false
}
