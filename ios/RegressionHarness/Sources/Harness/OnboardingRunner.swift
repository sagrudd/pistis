import Foundation
import PistisCore

@MainActor
public enum OnboardingRunner {
  public static func run(
    qr: String, fixture: OnboardingFixture, biometric: BiometricOutcome,
    state: inout ModelledOnboardingState, fault: OnboardingFault = .none,
    configurationDigest: Data? = nil, now: Date = OnboardingFixture.now
  ) -> OnboardingDiagnostic {
    var report = OnboardingDiagnostic()
    report.biometricInput = biometric
    do {
      let presentation = try fixture.presentation(
        qr: qr, digest: configurationDigest ?? fixture.configurationDigest, now: now)
      report.phase = "binding_preparation"
      let binding = try fixture.binding(presentation)
      if let checkpoint = state.checkpoint {
        report.phase = "retained_state_verification"
        try checkpoint.validate(binding: binding, fixture: fixture, now: now)
        if checkpoint.receipt != nil {
          report.outcome = "modelled_enrolled"
          return report
        }
      }
      report.phase = "authority_challenge_verification"
      let challengeExpiry = Date(
        timeIntervalSince1970: Double(binding.authorityChallengeExpiresAtMilliseconds) / 1_000)
      guard now < challengeExpiry else {
        report.failure = "expired_authority_challenge"
        return report
      }
      report.phase = "biometric"
      report.biometricRequested = true
      guard biometric == .success else {
        report.failure = "biometric_\(biometric.rawValue)"
        return report
      }
      if state.checkpoint == nil {
        report.phase = "registration_signing"
        report.effects.signingAttempts += 1
        let registration = try fixture.registration(binding)
        report.effects.signatures += 1
        state.checkpoint = OnboardingCheckpoint(binding: binding, registration: registration)
      }
      guard var checkpoint = state.checkpoint else { throw OnboardingFailure.retainedState }
      report.phase = "modelled_authority"
      if fault == .interruptedAfterRegistration {
        report.outcome = "interrupted"
        report.failure = fault.rawValue
        return report
      }
      report.effects.modelledSubmissions += 1
      if fault == .authorityUnavailable {
        report.outcome = "blocked"
        report.failure = fault.rawValue
        return report
      }
      let receipt = try fixture.receipt(
        binding: binding, registration: checkpoint.registration, fault: fault)
      report.phase = "receipt_verification"
      _ = try MobileEnrolmentReceiptV2.verify(
        returnedAuthorityBundle: fault == .wrongAuthorityBundle
          ? Data([0]) : presentation.authorityBundle,
        returnedRegistrationCOSE: fault == .wrongRegistration
          ? Data([0]) : checkpoint.registration,
        receiptCOSE: receipt, expectedRegistrationCOSE: checkpoint.registration,
        binding: binding, now: now)
      if fault == .interruptedAfterReceipt {
        report.outcome = "interrupted"
        report.failure = fault.rawValue
        return report
      }
      checkpoint.receipt = receipt
      state.checkpoint = checkpoint
      report.phase = "modelled_trust_commit"
      report.modelledTrustCommits = 1
      report.outcome = "modelled_enrolled"
      return report
    } catch {
      if let error = error as? FirstDevicePresentationError {
        switch error {
        case .wrongConfiguration: report.failure = "wrong_configuration"
        case .expired: report.failure = "expired_presentation"
        case .invalidSignature: report.failure = "invalid_presentation_signature"
        case .invalidAuthority: report.failure = "invalid_presentation_authority"
        case .malformed: report.failure = "malformed_presentation"
        }
      } else {
        report.failure =
          report.phase == "retained_state_verification"
          ? "retained_state_invalid" : "enrolment_verification_failed"
      }
      return report
    }
  }
}
