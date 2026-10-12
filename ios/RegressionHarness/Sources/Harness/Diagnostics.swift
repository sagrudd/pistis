import Foundation
import PistisCore

public enum BiometricOutcome: String, CaseIterable, Codable, Sendable {
  case success
  case rejected
  case cancelled
  case unavailable
  case notEnrolled = "not_enrolled"
  case lockedOut = "locked_out"

  var fact: LocalAuthenticationFact {
    switch self {
    case .success: .verified(method: .faceID, fallbackUsed: false)
    case .rejected: .failed
    case .cancelled: .cancelled
    case .unavailable, .notEnrolled: .unavailable
    case .lockedOut: .lockedOut
    }
  }
}

public struct SideEffects: Codable, Equatable, Sendable {
  public var signingAttempts = 0
  public var signatures = 0
  public var modelledSubmissions = 0
  public var modelledSessions = 0
  public var realNetworkRequests = 0
  public var privateKeyWrites = 0

  public init() {}
}

public struct Diagnostic: Encodable, Sendable {
  public let schema = "synoptikon.pistis-harness.diagnostic.v1"
  public var outcome: String
  public var phase: String
  public var failure: String?
  public var biometricInput: BiometricOutcome?
  public var biometricRequested = false
  public var effects = SideEffects()
  public let evidenceScope = "in_process_source"
  public let coveredCeremony = "enrolled_ordinary_login"
  public let supportedQRProfile = "PISTIS1_authentication_v2"
  public let physicalDeviceEvidence = false
  public let genuineServiceReceipt = false
  public let releaseAcceptance = false
  public let availableProductionCore = [
    "ProductionQRV2", "ProductionChallengeVerifier",
    "AuthenticationResponseEncoder", "CoseSign1", "ApprovalFlowReducer",
  ]
  public let modelled = [
    "enrolled_trust", "provider_identity", "FaceID", "SecureEnclave",
    "authority", "session", "ledger_snapshot_roundtrip", "approval_coordination",
  ]
  public let notExecuted = [
    "SwiftUI_ProductionCeremonyCoordinator", "Site_Root_genesis",
    "Site_X509_provisioning", "authority_custody", "first_device_enrolment", "provider_browser",
    "Apple_App_Attest", "Monas_service", "product_service",
    "native_keychain", "real_device",
  ]

  public init(outcome: String, phase: String, failure: String? = nil) {
    self.outcome = outcome
    self.phase = phase
    self.failure = failure
  }
}

func failureCode(_ error: Error) -> String {
  guard let error = error as? ProductionCeremonyError else { return "core_verification_failed" }
  switch error {
  case .malformedFrame: return "malformed_frame"
  case .oversizedFrame: return "oversized_frame"
  case .invalidChecksum: return "invalid_checksum"
  case .wrongTransferKind: return "wrong_transfer_kind"
  case .invalidChallenge: return "invalid_challenge"
  case .unknownInstallation: return "unknown_installation"
  case .inactiveInstallation: return "inactive_installation"
  case .keyMismatch: return "key_mismatch"
  case .invalidSignature: return "invalid_signature"
  case .wrongAudience: return "wrong_audience"
  case .wrongIdentity: return "wrong_identity"
  case .expired: return "expired"
  case .invalidEndpoint: return "invalid_endpoint"
  }
}

public func inspectUntrustedQR(_ text: String) -> Diagnostic {
  do {
    _ = try ProductionQRV2.decodeChallenge(text)
    return Diagnostic(
      outcome: "blocked", phase: "trust_verification", failure: "enrolment_required"
    )
  } catch {
    return Diagnostic(outcome: "failed", phase: "qr_verification", failure: failureCode(error))
  }
}
