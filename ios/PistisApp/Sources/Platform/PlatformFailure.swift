import Foundation

/// Non-sensitive failures exposed by platform adapters.
enum PlatformFailure: Error, Equatable, Sendable {
    case invalidConfiguration
    case secureHardwareUnavailable
    case keyCreationFailed
    case keyNotFound
    case keyInvalidated
    /// The Site Root Secure Enclave key required by a received ceremony is
    /// not present under the reviewed namespace. This is distinct from a
    /// generic device-key lookup failure so operators do not misdiagnose a
    /// valid QR as an unsupported carrier.
    case siteRootAuthorityKeyMissing
    /// The received ceremony names a different Site Root public key than the
    /// one held by this installation. No proof may be emitted in this case.
    case siteRootAuthorityKeyMismatch
    /// The Site Root key exists but Secure Enclave reports that its biometric
    /// binding is invalidated. Recovery must use the reviewed replacement or
    /// re-enrolment flow; the key is never silently replaced here.
    case siteRootAuthorityKeyInvalidated
    case publicKeyExtractionFailed
    case userVerificationUnavailable
    case userVerificationNotEnrolled
    case userVerificationCancelled
    case userVerificationLockedOut
    case signingFailed
    case malformedSignature
    case randomnessUnavailable
    case invalidOAuthCallback
    case oauthStateMismatch
    case oauthDenied
    case cameraPermissionDenied
    case cameraUnavailable
    case qrPayloadTooLarge
    case qrPayloadUnsupported
    /// A first-device presentation was recognisable as a Pistis invitation but
    /// failed verification. It must never fall through to ordinary login.
    case invalidFirstDevicePresentation
    case operationCancelled
    case productionEnvelopeUnavailable
    case siteRootAuthorityUnavailable
    /// The fixed broker rejected the first-device registration before Monas
    /// could issue a delegation. A fresh QR is required.
    case siteRootGenesisRegistrationRejected
    /// The fixed broker could not return a valid first-device delegation.
    case siteRootGenesisDelegationUnavailable
    /// The fixed broker remained pending until the bounded first-device wait
    /// elapsed. No proof was produced.
    case siteRootGenesisDelegationTimedOut
    /// The broker explicitly reported that the one-use delegation is no
    /// longer available.
    case siteRootGenesisDelegationExpired
    /// The broker explicitly reported that the one-use delegation was already
    /// consumed by an earlier attempt.
    case siteRootGenesisDelegationConsumed
    /// The fixed broker rejected the initial static proof completion.
    case siteRootGenesisCompletionRejected
    /// The iPhone could not reach the fixed broker or complete its protected
    /// TLS exchange. The stage-specific state remains visible to the user.
    case siteRootGenesisTransportUnavailable
    /// The protected first-install QR was already reserved by an earlier
    /// approval attempt and must be reissued by Monas.
    case siteX509PresentationAlreadyAttempted
    case enrolmentBeginRetryRequired
    case enrolmentRequired
    case existingEnrolmentMustBeRemoved
    case enrolmentReceiptInvalid
    case enrolmentStorageFailed
    case onboardingEventUploadUnavailable
    case onboardingEventUploadRejected
    case appAttestUnavailable
    case appAttestInvalidInput
    case appAttestKeyCreationFailed
    case appAttestAttestationFailed
    case appAttestAssertionFailed
    case custodyRewrapUnavailable
}

extension PlatformFailure {
    var safeUserMessage: String {
        switch self {
        case .cameraPermissionDenied:
            "Camera access is disabled. Allow camera access in Settings, then try again."
        case .cameraUnavailable:
            "No supported camera is available. Try again on an iPhone with a working camera."
        case .qrPayloadTooLarge:
            "This QR code is larger than the Pistis safety limit."
        case .qrPayloadUnsupported:
            "This is not a supported Pistis QR code."
        case .invalidFirstDevicePresentation:
            "This first-device invitation could not be verified. Request a newly issued QR from Monas."
        case .operationCancelled:
            "Scanning stopped before a code was captured."
        case .enrolmentRequired:
            "Enrol this installation through the authenticated system-browser flow before scanning."
        case .enrolmentBeginRetryRequired:
            "The host did not return a verifiable enrolment response. This exact attempt was retained; retry once or cancel and scan a fresh invitation."
        case .existingEnrolmentMustBeRemoved:
            "An existing Pistis identity already occupies this device. Remove or revoke it before beginning a new enrolment."
        case .enrolmentReceiptInvalid:
            "The host committed enrolment, but its signed response did not verify. The exact attempt was retained for safe retry."
        case .enrolmentStorageFailed:
            "The signed enrolment response verified, but Pistis could not retain it securely on this iPhone."
        case .siteRootAuthorityUnavailable:
            "The Monas Site Root authority is unavailable. No proof was submitted."
        case .siteRootGenesisRegistrationRejected:
            "Monas rejected this first-device registration. Return to the install window and request a newly issued QR. No proof was submitted."
        case .siteRootGenesisDelegationUnavailable:
            "Monas did not provide the protected first-device delegation. Return to the install window and request a newly issued QR. No proof was submitted."
        case .siteRootGenesisDelegationTimedOut:
            "Monas did not return the protected first-device delegation within 30 seconds. No proof was submitted; request a newly issued QR."
        case .siteRootGenesisDelegationExpired:
            "This first-device delegation has expired. Return to the install window and request a newly issued QR. No proof was submitted."
        case .siteRootGenesisDelegationConsumed:
            "This first-device delegation has already been consumed. Return to the install window and request a newly issued QR. No proof was submitted."
        case .siteRootGenesisCompletionRejected:
            "Monas rejected the initial Site Root proof completion. No proof was accepted; return to the install window and request a newly issued QR."
        case .siteRootGenesisTransportUnavailable:
            "Pistis could not reach the fixed Monas install service. No proof was submitted; check the connection and request a newly issued QR."
        case .siteX509PresentationAlreadyAttempted:
            "This protected Site X.509 QR has already been attempted. Return to the install window and request a newly issued code and QR."
        case .secureHardwareUnavailable:
            "Secure Enclave is unavailable on this device."
        case .appAttestUnavailable:
            "Apple App Attest is unavailable on this device. No device attestation was submitted."
        case .appAttestInvalidInput:
            "The attestation request is invalid. Scan a fresh request from Monas."
        case .appAttestKeyCreationFailed, .appAttestAttestationFailed,
             .appAttestAssertionFailed:
            "Pistis could not create device attestation. No device attestation was submitted."
        case .custodyRewrapUnavailable:
            "The protected custody ceremony is unavailable. No custody material was released."
        case .keyCreationFailed:
            "Pistis could not create the protected device key."
        case .keyInvalidated:
            "The protected device key is no longer valid. Remove the expired identity before enrolling again."
        case .siteRootAuthorityKeyMissing:
            "This iPhone has no Site Root authority key for this installation. No proof was submitted; use the governed Site Root recovery flow."
        case .siteRootAuthorityKeyMismatch:
            "This iPhone's Site Root authority key does not match Monas. No proof was submitted; use the governed authority replacement flow."
        case .siteRootAuthorityKeyInvalidated:
            "This iPhone's Site Root authority key was invalidated by Secure Enclave. No proof was submitted; use the governed authority replacement flow."
        case .userVerificationNotEnrolled:
            "Face ID is not enrolled. Configure Face ID in Settings, then try again."
        case .userVerificationLockedOut:
            "Face ID is locked. Unlock it in Settings or with the device passcode, then try again."
        case .userVerificationCancelled:
            "Face ID was cancelled before the protected key operation completed."
        case .userVerificationUnavailable:
            "Face ID is unavailable for this protected key operation."
        default:
            "Pistis could not complete this operation safely. Please try again."
        }
    }
}
