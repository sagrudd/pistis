import Foundation
@testable import PistisCore

enum Fixtures {
    static let now = Date(timeIntervalSince1970: 1_750_000_000)
    static let fingerprintA = try! SHA256Fingerprint(
        validating: String(repeating: "a", count: 64)
    )
    static let fingerprintB = try! SHA256Fingerprint(
        validating: String(repeating: "b", count: 64)
    )
    static let identityID = try! IdentityID(validating: "identity-1")
    static let installationID = try! InstallationID(validating: "installation-1")
    static let deviceID = try! DeviceID(validating: "device-1")
    static let challengeID = try! ChallengeID(validating: "challenge-1")

    static func identity(state: IdentityBindingState = .bound) -> ExternalIdentity {
        try! ExternalIdentity(
            id: identityID,
            provider: .github,
            providerSubject: "123456",
            displayName: "Ada",
            bindingState: state,
            boundDeviceID: deviceID,
            observedAt: now
        )
    }

    static func installation(paired: Bool = true) -> Installation {
        var installation = try! Installation(
            id: installationID,
            displayName: "Synoptikon Lab",
            observedFingerprint: fingerprintA
        )
        if paired {
            try! installation.pair(observedAt: now)
        }
        return installation
    }

    static func challenge(route: ChallengeRoute = .qr) -> ApprovalChallenge {
        try! ApprovalChallenge(
            id: challengeID,
            installationID: installationID,
            installationName: "Synoptikon Lab",
            installationFingerprint: fingerprintA,
            identityID: identityID,
            localUsername: "ada",
            purpose: .login,
            requestedStatement: "Sign in as ada",
            issuedAt: now,
            expiresAt: now.addingTimeInterval(120),
            route: route
        )
    }
}
