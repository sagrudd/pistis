import Foundation

private func installationNamespace(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

#if canImport(AVFoundation) && canImport(LocalAuthentication)
import AVFoundation
import LocalAuthentication
#endif

enum ReadinessState: Equatable, Sendable {
    case ready
    case actionRequired
    case unavailable
    case checking
}

struct ReadinessItem: Identifiable, Equatable, Sendable {
    let id: String
    let title: String
    let detail: String
    let state: ReadinessState
}

/// Coarse, non-secret capability state for the passwordless ceremony.
///
/// It deliberately carries no key identifiers, QR content, provider identity,
/// endpoint, or attacker-controlled display value.
struct PasswordlessReadiness: Equatable, Sendable {
    let camera: ReadinessItem
    let faceID: ReadinessItem
    let deviceKey: ReadinessItem
    let authorityKey: ReadinessItem
    let verifier: ReadinessItem

    var items: [ReadinessItem] {
        [camera, faceID, deviceKey, authorityKey, verifier]
    }

    var approvalEnabled: Bool {
        items.allSatisfy { $0.state == .ready }
    }

    static let checking = PasswordlessReadiness(
        camera: item("camera", "Camera", "Checking camera permission.", .checking),
        faceID: item("face-id", "Face ID", "Checking Face ID capability.", .checking),
        deviceKey: item("device-key", "Device signing key", "Checking device key.", .checking),
        authorityKey: item(
            "authority-key",
            "Installation authority",
            "Checking enrolled installation trust.",
            .checking
        ),
        verifier: item(
            "verifier",
            "Production verifier",
            "Checking protocol availability.",
            .checking
        )
    )

    static func item(
        _ id: String,
        _ title: String,
        _ detail: String,
        _ state: ReadinessState
    ) -> ReadinessItem {
        ReadinessItem(id: id, title: title, detail: detail, state: state)
    }
}

@MainActor
enum PasswordlessReadinessProbe {
    static func current(
        trustStore: any InstallationTrustStoring = InstallationTrustKeychain.shared
    ) async -> PasswordlessReadiness {
        let enrollment = try? await trustStore.activeEnrollment()
        let hasTrust = enrollment != nil
        return PasswordlessReadiness(
            camera: camera(),
            faceID: faceID(),
            deviceKey: deviceKey(installationID: enrollment?.trust.installationID),
            authorityKey: .init(
                id: "authority-key",
                title: "Installation authority",
                detail: hasTrust
                    ? "Authenticated installation trust is stored in Keychain."
                    : "No authenticated installation trust is stored.",
                state: hasTrust ? .ready : .actionRequired
            ),
            verifier: .init(
                id: "verifier",
                title: "Production verifier",
                detail: "The accepted QR v2 and COSE verifier is available.",
                state: .ready
            )
        )
    }

    private static func camera() -> ReadinessItem {
        #if canImport(AVFoundation)
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            return .init(
                id: "camera",
                title: "Camera",
                detail: "Camera permission is available.",
                state: .ready
            )
        case .notDetermined:
            return .init(
                id: "camera",
                title: "Camera",
                detail: "Permission will be requested when scanning starts.",
                state: .actionRequired
            )
        default:
            return .init(
                id: "camera",
                title: "Camera",
                detail: "Camera permission is unavailable.",
                state: .unavailable
            )
        }
        #else
        return .init(
            id: "camera",
            title: "Camera",
            detail: "Camera capability is unavailable.",
            state: .unavailable
        )
        #endif
    }

    private static func faceID() -> ReadinessItem {
        #if canImport(LocalAuthentication)
        let context = LAContext()
        var error: NSError?
        let available = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &error
        )
        guard available, context.biometryType == .faceID else {
            return .init(
                id: "face-id",
                title: "Face ID",
                detail: "Face ID is unavailable or not enrolled.",
                state: .unavailable
            )
        }
        return .init(
            id: "face-id",
            title: "Face ID",
            detail: "Face ID is available for explicit verification.",
            state: .ready
        )
        #else
        return .init(
            id: "face-id",
            title: "Face ID",
            detail: "Face ID capability is unavailable.",
            state: .unavailable
        )
        #endif
    }

    private static func deviceKey(installationID: Data?) -> ReadinessItem {
        #if canImport(LocalAuthentication) && canImport(Security)
        guard let installationID else {
            return .init(
                id: "device-key",
                title: "Device signing key",
                detail: "Create the device signing key during enrolment.",
                state: .actionRequired
            )
        }
        do {
            let signer = try SecureEnclaveSigner(
                namespace: installationNamespace(installationID),
                authenticationReason: "Verify this Pistis request"
            )
            if try signer.hasExistingKey() {
                return .init(
                    id: "device-key",
                    title: "Device signing key",
                    detail: "A device-bound signing key is available.",
                    state: .ready
                )
            }
            return .init(
                id: "device-key",
                title: "Device signing key",
                detail: "Create the device signing key during enrolment.",
                state: .actionRequired
            )
        } catch {
            return .init(
                id: "device-key",
                title: "Device signing key",
                detail: "The device signing key cannot be used.",
                state: .unavailable
            )
        }
        #else
        return .init(
            id: "device-key",
            title: "Device signing key",
            detail: "Secure Enclave key capability is unavailable.",
            state: .unavailable
        )
        #endif
    }
}
