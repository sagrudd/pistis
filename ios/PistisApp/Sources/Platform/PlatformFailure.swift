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
}
