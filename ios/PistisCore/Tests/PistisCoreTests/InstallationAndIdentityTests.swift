import Testing
@testable import PistisCore

@Test func installationTrustChangeBlocksApprovalUntilExplicitRepair() throws {
    var installation = Fixtures.installation()
    try installation.observe(
        fingerprint: Fixtures.fingerprintB,
        observedAt: Fixtures.now.addingTimeInterval(10)
    )

    #expect(installation.trustState == .trustChanged)
    #expect(!installation.mayApprove)
    #expect(throws: InstallationTrustError.fingerprintMismatch) {
        try installation.repair(
            confirmedFingerprint: Fixtures.fingerprintA,
            at: Fixtures.now.addingTimeInterval(11)
        )
    }

    try installation.repair(
        confirmedFingerprint: Fixtures.fingerprintB,
        at: Fixtures.now.addingTimeInterval(12)
    )
    #expect(installation.trustState == .trusted)
    #expect(installation.mayApprove)
}

@Test func revokedInstallationCannotBePairedAgain() throws {
    var installation = Fixtures.installation()
    installation.revoke()
    #expect(throws: InstallationTrustError.revoked) {
        try installation.pair(observedAt: Fixtures.now)
    }
}

@Test func stableIdentityCannotChangeProviderSubject() throws {
    var store = IdentityStore()
    try store.record(Fixtures.identity())
    let conflicting = try ExternalIdentity(
        id: Fixtures.identityID,
        provider: .github,
        providerSubject: "different",
        displayName: "Ada",
        bindingState: .bound,
        boundDeviceID: Fixtures.deviceID,
        observedAt: Fixtures.now
    )
    #expect(throws: IdentityStoreError.stableIdentityConflict) {
        try store.record(conflicting)
    }
}

@Test func fingerprintRequiresCanonicalSHA256Hex() {
    #expect(SHA256Fingerprint(rawValue: String(repeating: "A", count: 64))?.rawValue ==
            String(repeating: "a", count: 64))
    #expect(SHA256Fingerprint(rawValue: "abc") == nil)
    #expect(SHA256Fingerprint(rawValue: String(repeating: "g", count: 64)) == nil)
}
