import Crypto
import Foundation
import PistisCore

/// Model state only. This is not Monas' durable authority or session store.
public struct ModelledLedger: Codable, Sendable {
  var owner: String?
  var consumedChallenges: Set<String> = []
  public init() {}
}

private struct FixtureTrust: InstallationTrustReading {
  let trust: InstallationTrustRecord?
  func record(installationID: Data) async throws -> InstallationTrustRecord? {
    trust?.installationID == installationID ? trust : nil
  }
}

@MainActor
public enum CeremonyRunner {
  public static func run(
    qr: String,
    fixture: EnrolledFixture,
    biometric: BiometricOutcome,
    denied: Bool = false,
    enrolled: Bool = true,
    ledger: inout ModelledLedger,
    now: Date = EnrolledFixture.now
  ) async -> Diagnostic {
    var report = Diagnostic(outcome: "failed", phase: "qr_verification")
    report.biometricInput = biometric
    do {
      let challenge = try await ProductionChallengeVerifier.verify(
        qrText: qr,
        trustRepository: FixtureTrust(trust: enrolled ? fixture.trust : nil),
        expectedExternalIdentityID: fixture.externalID,
        now: now
      )
      report.phase = "modelled_ledger"
      let owner = hex(
        Data(
          SHA256.hash(
            data: fixture.trust.installationPublicKey
              + fixture.deviceKey.publicKey.compressedRepresentation
          )))
      guard ledger.owner == nil || ledger.owner == owner else {
        report.failure = "ledger_identity_mismatch"
        return report
      }
      let challengeID = hex(challenge.challengeID)
      guard !ledger.consumedChallenges.contains(challengeID) else {
        report.failure = "replay"
        return report
      }
      let approval = try approvalChallenge(challenge)
      let identity = try ExternalIdentity(
        id: approval.identityID, provider: .github, providerSubject: "123456789",
        displayName: "Fixture identity", bindingState: .bound,
        boundDeviceID: DeviceID(validating: hex(fixture.responseContext.deviceID)),
        observedAt: now
      )
      var installation = try Installation(
        id: approval.installationID, displayName: approval.installationName,
        observedFingerprint: approval.installationFingerprint
      )
      try installation.pair(observedAt: now)
      let reducer = ApprovalFlowReducer()
      var state = reducer.reduce(
        state: .idle,
        event: .acquired(
          challenge: approval, identity: identity, installation: installation, now: now
        )
      )
      guard case .awaitingDecision = state else {
        report.failure = "approval_validation_failed"
        return report
      }
      state = reducer.reduce(state: state, event: .decide(denied ? .denied : .approved, at: now))
      report.phase = "biometric"
      report.biometricRequested = true
      state = reducer.reduce(state: state, event: .localAuthentication(biometric.fact))
      guard case .awaitingSignature = state else {
        report.failure = "biometric_\(biometric.rawValue)"
        return report
      }
      report.phase = "response_preparation"
      let milliseconds = UInt64(now.timeIntervalSince1970 * 1000)
      let payload = try AuthenticationResponseEncoder.payload(
        challenge: challenge, context: fixture.responseContext,
        decision: denied ? .denied : .approved,
        issuedAtMilliseconds: milliseconds, userVerifiedAtMilliseconds: milliseconds
      )
      report.phase = "signing"
      report.effects.signingAttempts += 1
      let envelope = try EnrolledFixture.sign(
        payload, keyID: fixture.responseContext.deviceKeyID, using: fixture.deviceKey
      )
      report.effects.signatures += 1
      state = reducer.reduce(
        state: state,
        event: .signature(
          .created(
            keyID: hex(fixture.responseContext.deviceKeyID),
            signatureDigest: try SHA256Fingerprint(
              validating: hex(Data(SHA256.hash(data: envelope))))
          ))
      )
      guard case .awaitingTransfer = state else {
        report.failure = "signature_transition_failed"
        return report
      }
      report.phase = "modelled_authority"
      report.effects.modelledSubmissions += 1
      let cose = try CoseSign1.decode(envelope)
      let signature = try P256.Signing.ECDSASignature(rawRepresentation: cose.signature)
      guard cose.keyID == fixture.responseContext.deviceKeyID, cose.payload == payload,
        fixture.deviceKey.publicKey.isValidSignature(signature, for: cose.signatureStructure())
      else {
        report.failure = "response_verification_failed"
        return report
      }
      state = reducer.reduce(
        state: state, event: .transfer(.submitted(route: .qr, receiptID: nil))
      )
      state = reducer.reduce(
        state: state,
        event: .serverVerification(.accepted(evidenceID: try EvidenceID(validating: "model-only")))
      )
      guard case .finished = state else {
        report.failure = "authority_transition_failed"
        return report
      }
      ledger.owner = owner
      ledger.consumedChallenges.insert(challengeID)
      report.effects.modelledSessions = denied ? 0 : 1
      report.outcome = denied ? "denied" : "modelled_session"
      report.failure = nil
      return report
    } catch {
      report.failure = failureCode(error)
      return report
    }
  }

  private static func approvalChallenge(
    _ challenge: VerifiedAuthenticationChallenge
  ) throws -> ApprovalChallenge {
    try ApprovalChallenge(
      id: ChallengeID(validating: hex(challenge.challengeID)),
      installationID: InstallationID(validating: hex(challenge.installationID)),
      installationName: challenge.installationName,
      installationFingerprint: SHA256Fingerprint(
        validating: hex(challenge.installationFingerprint)),
      identityID: IdentityID(validating: hex(challenge.externalIdentityID)),
      localUsername: challenge.localUsername, purpose: .login,
      requestedStatement: "Fixture login",
      issuedAt: Date(
        timeIntervalSince1970: Double(challenge.issuedAtMilliseconds) / 1000
      ),
      expiresAt: Date(timeIntervalSince1970: Double(challenge.expiresAtMilliseconds) / 1000),
      route: .qr
    )
  }
}
