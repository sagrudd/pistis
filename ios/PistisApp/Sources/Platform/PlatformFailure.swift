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
    case enrolmentRequired
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
        default:
            "Pistis could not complete this operation safely. Please try again."
        }
    }
}
