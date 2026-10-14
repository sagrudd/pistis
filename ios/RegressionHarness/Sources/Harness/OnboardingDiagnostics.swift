import Foundation

public enum OnboardingFault: String, CaseIterable, Sendable {
  case none
  case authorityUnavailable = "authority_unavailable"
  case interruptedAfterRegistration = "interrupted_after_registration"
  case interruptedAfterReceipt = "interrupted_after_receipt"
  case wrongAuthorityBundle = "wrong_authority_bundle"
  case wrongRegistration = "wrong_registration"
  case wrongReceiptSigner = "wrong_receipt_signer"
  case wrongDevice = "wrong_device"
  case expiredReceipt = "expired_receipt"
  case inactiveReceipt = "inactive_receipt"
}

public struct OnboardingDiagnostic: Encodable, Sendable {
  public let schema = "synoptikon.pistis-onboarding.diagnostic.v1"
  public var outcome = "failed"
  public var phase = "presentation_verification"
  public var failure: String?
  public var biometricInput: BiometricOutcome?
  public var biometricRequested = false
  public var effects = SideEffects()
  public var modelledTrustCommits = 0
  public let evidenceScope = "in_process_source"
  public let coveredCeremony = "first_device_enrolment"
  public let supportedQRProfile = "PISTIS1_first_device_v4"
  public let availableProductionCore = [
    "FirstDevicePresentationV4", "EnrolmentBindingV1", "MobileEnrolmentReceiptV2", "CoseSign1",
  ]
  public let modelled = [
    "FaceID", "SecureEnclave", "provider_identity", "authority_receipt_issuer",
    "retained_state", "trust_commit", "approval_coordination",
  ]
  public let notExecuted = [
    "SwiftUI_enrolment_coordinator", "Site_Root_genesis", "Site_X509", "custody",
    "provider_browser", "Apple_App_Attest", "native_keychain", "Monas_service", "real_device",
  ]
  public let genuineServiceReceipt = false
  public let physicalDeviceEvidence = false
  public let releaseAcceptance = false
  public let checkpointRollbackProtection = false

  public init() {}
}

enum OnboardingFailure: Error { case fixture, retainedState }
