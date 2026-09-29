import CryptoKit
import Foundation

/// Confirms the original PXRB/v1 owner approval and native observation against
/// their durable mutation-time record. PXRA/PXRP alone cannot establish this.
/// Implementations must consume locally retained, independently authenticated
/// evidence, perform no network access, and never infer mutation time from
/// dispatch time or a generic record `updated_at` field.
protocol SiteRootAckOfflineAuthorizationVerifying: Sendable {
  func verifyOriginalAuthorizationAndMutation(
    for presentation: UnsignedSiteRootConvergenceAssertionV2
  ) throws -> Bool
}

/// Safe default until Pistis has an independently retained PXRB/native
/// observation source and its verifier has passed cross-service review.
struct UnavailableSiteRootAckOfflineAuthorizationVerifier:
  SiteRootAckOfflineAuthorizationVerifying
{
  func verifyOriginalAuthorizationAndMutation(
    for _: UnsignedSiteRootConvergenceAssertionV2
  ) throws -> Bool { false }
}

/// Local verifier and exact-response producer for one signed PXRP/v1 file.
///
/// This service has no transport dependency. It verifies the app-bundle pin,
/// current enrolled ACK registration, current signed Site Root profile and
/// fresh presentation immediately before using the existing ACK key.
struct OfflineSiteRootAcknowledgementV1 {
  static func verify(
    frame: Data,
    pin: ProxenosPXRAKeyPinV1?,
    registration: SiteRootConvergenceAckRecordV2,
    nowUnixMilliseconds: UInt64
  ) throws -> ProxenosPXRAEnvelopeV1 {
    guard let pin, registration.siteUUID == pin.siteUUID,
      registration.generation > 0,
      let targetID = SiteRootConvergenceEncoding.base64URL(
        registration.targetIDB64URL
      ), targetID.count == 32,
      let ackPublic = SiteRootConvergenceEncoding.base64URL(
        registration.ackPublicKeyB64URL
      ), ackPublic.count == 33
    else { throw PlatformFailure.siteRootAuthorityUnavailable }
    return try ProxenosPXRAEnvelopeV1(
      frame: frame,
      pin: pin,
      expectedSiteUUID: registration.siteUUID,
      expectedTargetID: targetID,
      expectedAckGeneration: registration.generation,
      nowUnixMilliseconds: nowUnixMilliseconds
    )
  }

  /// Requires explicit Face ID and signs the exact imported PXRA bytes with
  /// the already-present, registered Secure Enclave ACK key. It never
  /// creates keys, changes the registration, or sends data over a network.
  static func sign(
    frame: Data,
    pin: ProxenosPXRAKeyPinV1?,
    registration: SiteRootConvergenceAckRecordV2,
    trustPolicy: MonasServerTrustPolicy,
    authorizationVerifier: any SiteRootAckOfflineAuthorizationVerifying,
    nowUnixMilliseconds: UInt64,
    authenticate: () async throws -> FaceIDCeremonyContext = {
      try await FaceIDCeremonyContext.authenticate(
        reason: "Verify this Site Root acknowledgement presentation"
      )
    }
  ) async throws -> Data {
    let verified = try verify(
      frame: frame, pin: pin, registration: registration,
      nowUnixMilliseconds: nowUnixMilliseconds
    )
    guard
      try authorizationVerifier.verifyOriginalAuthorizationAndMutation(
        for: verified.presentation
      )
    else { throw PlatformFailure.siteRootAuthorityUnavailable }
    guard case .siteRootGeneration(_, let fingerprint, let generation) = trustPolicy,
      fingerprint == verified.presentation.rootFingerprint,
      generation == verified.presentation.rootGeneration
    else { throw PlatformFailure.siteRootAuthorityUnavailable }

    let ceremony = try await authenticate()
    let siteRootSigner = try SecureEnclaveSigner(
      namespace: "site-root-delegation-v1",
      authenticationReason: "Verify this Site Root acknowledgement presentation"
    )
    let acknowledgementSigner = try SecureEnclaveSigner(
      namespace: "site-root-convergence-ack-v2",
      authenticationReason: "Verify this Site Root acknowledgement presentation"
    )
    guard try siteRootSigner.hasExistingKey(),
      try acknowledgementSigner.hasExistingKey()
    else { throw PlatformFailure.keyNotFound }
    let siteRootPublic = try siteRootSigner.publicKey(using: ceremony).compressedSEC1
    let ackPublic = try acknowledgementSigner.publicKey(using: ceremony).compressedSEC1
    let siteRootTargetID = Data(SHA256.hash(data: siteRootPublic))
    guard
      SiteRootConvergenceEncoding.encode(siteRootTargetID)
        == registration.targetIDB64URL,
      SiteRootConvergenceEncoding.encode(ackPublic)
        == registration.ackPublicKeyB64URL,
      verified.presentation.siteUUIDText == registration.siteUUID,
      verified.presentation.ackKeyGeneration == registration.generation
    else { throw PlatformFailure.siteRootAuthorityUnavailable }

    // Re-evaluate time after Face ID, since the five-minute challenge may
    // expire while the user is reviewing or authenticating.
    let currentTime = try Self.nowUnixMilliseconds()
    let current = try verify(
      frame: frame, pin: pin, registration: registration,
      nowUnixMilliseconds: currentTime
    )
    guard
      try authorizationVerifier.verifyOriginalAuthorizationAndMutation(
        for: current.presentation
      )
    else { throw PlatformFailure.siteRootAuthorityUnavailable }
    guard current.unsignedPXRA == verified.unsignedPXRA,
      case .siteRootGeneration(_, let currentFingerprint, let currentGeneration) = trustPolicy,
      currentFingerprint == current.presentation.rootFingerprint,
      currentGeneration == current.presentation.rootGeneration
    else { throw PlatformFailure.siteRootAuthorityUnavailable }

    return try RetainedSiteRootAcknowledgementV2.signedAcknowledgement(
      current.unsignedPXRA,
      record: registration,
      siteRootPublic: siteRootPublic,
      ackPublic: ackPublic,
      nowMilliseconds: currentTime,
      sign: { try acknowledgementSigner.sign(message: $0, using: ceremony) }
    )
  }

  private static func nowUnixMilliseconds() throws -> UInt64 {
    let value = Date().timeIntervalSince1970 * 1_000
    guard value >= 0, value <= TimeInterval(UInt64.max) else {
      throw PlatformFailure.invalidConfiguration
    }
    return UInt64(value)
  }
}

/// A separate non-authority check that the pre-update ACK Secure Enclave key
/// still signs after an in-place update. No proof is retained or submitted.
enum SiteRootAckContinuityServiceV1 {
  static func check(
    preUpdatePublicKey: Data,
    preUpdateGeneration: UInt64,
    registration: SiteRootConvergenceAckRecordV2
  ) async throws {
    guard preUpdateGeneration > 0,
      preUpdatePublicKey.count == 33,
      registration.generation == preUpdateGeneration,
      registration.ackPublicKeyB64URL
        == SiteRootConvergenceEncoding.encode(preUpdatePublicKey)
    else { throw PlatformFailure.siteRootAuthorityUnavailable }

    let ceremony = try await FaceIDCeremonyContext.authenticate(
      reason: "Check the retained Site Root acknowledgement key"
    )
    let signer = try SecureEnclaveSigner(
      namespace: "site-root-convergence-ack-v2",
      authenticationReason: "Check the retained Site Root acknowledgement key"
    )
    guard try signer.hasExistingKey() else { throw PlatformFailure.keyNotFound }
    let currentPublicKey = try signer.publicKey(using: ceremony).compressedSEC1
    guard currentPublicKey == preUpdatePublicKey else {
      throw PlatformFailure.siteRootAuthorityUnavailable
    }
    let probe = try SiteRootAckContinuityProbeV1.generate(
      siteUUID: registration.siteUUID, generation: preUpdateGeneration
    )
    _ = try probe.sign(
      using: { try signer.sign(message: $0, using: ceremony) },
      preUpdatePublicKey: preUpdatePublicKey,
      preUpdateGeneration: preUpdateGeneration
    )
  }
}

/// Separate App Attest continuity challenge producer. It uses only the exact
/// pre-update key reference and returns the assertion in memory for an
/// independent verifier; it does not enrol, replace, persist or submit it.
protocol SiteRootAppAttestContinuityVerifying: Sendable {
  func verifyContinuityAssertion(
    keyID: String,
    challenge: Data,
    assertion: Data
  ) async throws -> Bool
}

struct SiteRootAppAttestContinuityAssertionV1: Sendable {
  let keyID: String
  let challenge: Data
  let assertion: Data
}

enum SiteRootAppAttestContinuityProbeV1 {
  static let domain = Data("mnemosyne.pistis.app-attest-continuity.v1\0".utf8)

  static func challenge(siteUUID: String, nonce: Data) throws -> Data {
    guard let site = SiteRootConvergenceEncoding.uuidBytes(siteUUID),
      nonce.count == 32, !nonce.allSatisfy({ $0 == 0 })
    else { throw PlatformFailure.appAttestInvalidInput }
    return domain + site + nonce
  }

  static func assertion(
    client: AppleAppAttestClient,
    siteUUID: String,
    preUpdateKeyID: String
  ) async throws -> SiteRootAppAttestContinuityAssertionV1 {
    guard let keyID = Data(base64Encoded: preUpdateKeyID), keyID.count == 32 else {
      throw PlatformFailure.appAttestInvalidInput
    }
    var generator = SystemRandomNumberGenerator()
    let nonce = Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    let challengeBytes = try challenge(siteUUID: siteUUID, nonce: nonce)
    let hash = Data(SHA256.hash(data: challengeBytes))
    let assertion = try await client.prepareSiteRootAckContinuityAssertion(
      expectedKeyID: preUpdateKeyID,
      clientDataHash: hash
    )
    return SiteRootAppAttestContinuityAssertionV1(
      keyID: preUpdateKeyID,
      challenge: challengeBytes,
      assertion: assertion
    )
  }

  /// Requires explicit acceptance by the independent App Attest verifier.
  /// This separate gate is never folded into a Site Root ACK signature.
  static func requireAccepted(
    client: AppleAppAttestClient,
    verifier: any SiteRootAppAttestContinuityVerifying,
    siteUUID: String,
    preUpdateKeyID: String
  ) async throws {
    let result = try await assertion(
      client: client, siteUUID: siteUUID,
      preUpdateKeyID: preUpdateKeyID
    )
    guard
      try await verifier.verifyContinuityAssertion(
        keyID: result.keyID,
        challenge: result.challenge,
        assertion: result.assertion
      )
    else { throw PlatformFailure.appAttestAssertionFailed }
  }
}
