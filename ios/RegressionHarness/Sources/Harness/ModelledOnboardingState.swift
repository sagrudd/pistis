import Crypto
import Foundation
import PistisCore

/// In-memory snapshot evidence only; not the app's keychain or a service journal.
public struct ModelledOnboardingState: Sendable {
  var checkpoint: OnboardingCheckpoint?
  public init() {}

  public func snapshot() throws -> Data? {
    guard let checkpoint else { return nil }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(checkpoint)
  }

  @MainActor
  public static func restore(
    _ bytes: Data, fixture: OnboardingFixture, now: Date = OnboardingFixture.now
  ) throws -> Self {
    guard bytes.count <= 8_192 else { throw OnboardingFailure.retainedState }
    let checkpoint = try JSONDecoder().decode(OnboardingCheckpoint.self, from: bytes)
    var state = Self()
    state.checkpoint = checkpoint
    // Canonical equality also rejects unknown/duplicate fields and legacy envelopes.
    guard try state.snapshot() == bytes else { throw OnboardingFailure.retainedState }
    let presentation = try fixture.presentation(
      qr: fixture.qr, digest: fixture.configurationDigest, now: now)
    let binding = try fixture.binding(presentation)
    try checkpoint.validate(binding: binding, fixture: fixture, now: now)
    return state
  }
}

struct OnboardingCheckpoint: Codable, Sendable {
  let schema: String
  let bindingDigest: Data
  let registration: Data
  var receipt: Data?

  init(binding: EnrolmentBindingInput, registration: Data) {
    schema = "synoptikon.pistis-onboarding.modelled-checkpoint.v1"
    bindingDigest = Data(SHA256.hash(data: EnrolmentBindingV1.payload(binding)))
    self.registration = registration
  }

  @MainActor
  func validate(binding: EnrolmentBindingInput, fixture: OnboardingFixture, now: Date) throws {
    guard schema == "synoptikon.pistis-onboarding.modelled-checkpoint.v1",
      bindingDigest == Data(SHA256.hash(data: EnrolmentBindingV1.payload(binding))),
      registration.count <= 2_048
    else { throw OnboardingFailure.retainedState }
    let cose = try CoseSign1.decode(registration)
    let signature = try P256.Signing.ECDSASignature(rawRepresentation: cose.signature)
    guard cose.keyID == binding.deviceKeyID,
      cose.payload == EnrolmentBindingV1.payload(binding),
      fixture.deviceKey.publicKey.isValidSignature(signature, for: cose.signatureStructure())
    else { throw OnboardingFailure.retainedState }
    if let receipt {
      _ = try MobileEnrolmentReceiptV2.verify(
        returnedAuthorityBundle: binding.presentation.authorityBundle,
        returnedRegistrationCOSE: registration, receiptCOSE: receipt,
        expectedRegistrationCOSE: registration, binding: binding, now: now)
    }
  }
}
