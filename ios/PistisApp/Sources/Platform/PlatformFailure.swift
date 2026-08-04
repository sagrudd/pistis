import Foundation

/// Non-sensitive failures exposed by platform adapters.
enum PlatformFailure: Error, Equatable, Sendable {
    case invalidConfiguration
    case secureHardwareUnavailable
    case keyCreationFailed
    case keyNotFound
    case keyInvalidated
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
    case operationCancelled
    case productionEnvelopeUnavailable
    case siteRootAuthorityUnavailable
    case enrolmentBeginRetryRequired
    case enrolmentRequired
    case existingEnrolmentMustBeRemoved
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
        case .operationCancelled:
            "Scanning stopped before a code was captured."
        case .enrolmentRequired:
            "Enrol this installation through the authenticated system-browser flow before scanning."
        case .enrolmentBeginRetryRequired:
            "The host did not return a verifiable enrolment response. This exact attempt was retained; retry once or cancel and scan a fresh invitation."
        case .existingEnrolmentMustBeRemoved:
            "An existing Pistis identity already occupies this device. Remove or revoke it before beginning a new enrolment."
        case .siteRootAuthorityUnavailable:
            "The Monas Site Root authority is unavailable. No proof was submitted."
        case .secureHardwareUnavailable:
            "Secure Enclave is unavailable on this device."
        case .keyCreationFailed:
            "Pistis could not create the protected device key."
        case .keyInvalidated:
            "The protected device key is no longer valid. Remove the expired identity before enrolling again."
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
