import Foundation
import LocalAuthentication

protocol MTGSRecoveryExecuting: Sendable {
    func execute(_ presentation: MTGSRecoveryPresentationV1) async throws
}

struct UnavailableMTGSRecoveryService: MTGSRecoveryExecuting {
    func execute(_: MTGSRecoveryPresentationV1) async throws {
        throw PlatformFailure.siteRootAuthorityUnavailable
    }
}

/// Purpose-separated physical-iPhone recovery operation. A fresh Face ID
/// evaluation is required immediately before App Attest signs the exact QR
/// challenge and the result is sent once to the fixed pinned Monas route.
struct ProductionMTGSRecoveryService: MTGSRecoveryExecuting {
    private let transport: MonasAppAttestTransport
    private let appAttestClient: AppleAppAttestClient

    init(
        siteRootTransport: MonasSiteRootDelegationTransport,
        appAttestClient: AppleAppAttestClient = AppleAppAttestClient()
    ) throws {
        transport = try siteRootTransport.appAttestTransport()
        self.appAttestClient = appAttestClient
    }

    func execute(_ presentation: MTGSRecoveryPresentationV1) async throws {
        try await MTGSRecoveryFaceIDGate.requireFreshAttendance()
        let assertion = try await appAttestClient.prepareMTGSRecoveryAssertion(
            presentation: presentation
        )
        try await transport.submitMTGSRecoveryAssertion(assertion)
    }
}

enum MTGSRecoveryFaceIDGate {
    static func requireFreshAttendance() async throws {
        let context = LAContext()
        context.localizedCancelTitle = "Deny"
        context.localizedReason = "Approve this exact Site Trust recovery"
        context.interactionNotAllowed = false
        var error: NSError?
        guard context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: &error
        ), context.biometryType == .faceID else {
            throw map(error)
        }
        do {
            guard try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: context.localizedReason
            ), context.biometryType == .faceID else {
                throw PlatformFailure.userVerificationCancelled
            }
        } catch let failure as PlatformFailure {
            throw failure
        } catch let failure as LAError {
            throw map(failure as NSError)
        } catch {
            throw PlatformFailure.userVerificationUnavailable
        }
    }

    private static func map(_ error: NSError?) -> PlatformFailure {
        guard let error, let code = LAError.Code(rawValue: error.code) else {
            return .userVerificationUnavailable
        }
        switch code {
        case .biometryNotEnrolled: return .userVerificationNotEnrolled
        case .biometryLockout: return .userVerificationLockedOut
        case .userCancel, .appCancel, .systemCancel: return .userVerificationCancelled
        default: return .userVerificationUnavailable
        }
    }
}
