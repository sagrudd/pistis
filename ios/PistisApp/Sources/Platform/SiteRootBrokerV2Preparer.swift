import Foundation

/// Serialises key preparation for an operation throughout this app process.
private actor BrokerV2PreparationGate {
    static let shared = BrokerV2PreparationGate()
    private var active = Set<UUID>()
    func claim(_ id: UUID) -> Bool { active.insert(id).inserted }
    func release(_ id: UUID) { active.remove(id) }
}

/// Prepares and durably stages a V2 request without sending it or accepting B.
/// This inactive primitive cannot authenticate a broker/installation join.
struct SiteRootBrokerV2Preparer: Sendable {
    let storage: ScopedAppAttestStore
    let appAttest: AppleAppAttestClient

    func prepare(
        presentation: SiteRootBrokerPresentationV2,
        attemptID: UUID,
        siteRootKey: SiteRootKeyRegistrationV1,
        nowMillis: @Sendable () -> UInt64
    ) async throws -> ScopedAppAttestPending {
        guard await BrokerV2PreparationGate.shared.claim(attemptID) else {
            throw PlatformFailure.enrolmentBeginRetryRequired
        }
        do {
            let result = try await prepareClaimed(
                presentation: presentation, attemptID: attemptID,
                siteRootKey: siteRootKey, nowMillis: nowMillis
            )
            await BrokerV2PreparationGate.shared.release(attemptID)
            return result
        } catch {
            await BrokerV2PreparationGate.shared.release(attemptID)
            throw error
        }
    }

    private func prepareClaimed(
        presentation: SiteRootBrokerPresentationV2,
        attemptID: UUID,
        siteRootKey: SiteRootKeyRegistrationV1,
        nowMillis: @Sendable () -> UInt64
    ) async throws -> ScopedAppAttestPending {
        guard nowMillis() < presentation.expiresAt else {
            throw PlatformFailure.siteRootGenesisPresentationExpired
        }
        var uuid = attemptID.uuid
        let operation = withUnsafeBytes(of: &uuid) { Data($0) }
        if let retained = try storage.pending(attemptID: attemptID) {
            guard retained.correlation == presentation.correlation,
                  retained.registrationReference == presentation.reference,
                  retained.siteClaim == presentation.site,
                  retained.environmentClaim == "Production" else {
                throw PlatformFailure.invalidConfiguration
            }
            try SiteRootBrokerRegistrationWireV2.validate(
                retained.preparedRegistration, presentation: presentation, operationID: operation
            )
            let values = try StrictJSONObject(data: retained.preparedRegistration, maximumBytes: 12 * 1024).values
            guard case let .object(root)? = values["site_root_key"],
                  root["device_key_id"] == .string(siteRootKey.deviceKeyID),
                  root["public_key_compressed_sec1_base64url"] == .string(
                    SiteRootBrokerPresentationV2.encode(siteRootKey.publicKeyCompressedSEC1)),
                  case let .object(apple)? = values["app_attest_registration"],
                  let keyBytes = PendingAppAttestReplacementKeyV1.canonicalKeyID(retained.keyID),
                  apple["key_id_b64url"] == .string(SiteRootBrokerPresentationV2.encode(keyBytes))
            else { throw PlatformFailure.invalidConfiguration }
            return retained
        }
        try SiteRootBrokerRegistrationWireV2.validateSiteRootKey(siteRootKey)
        let hash = try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
            operationID: operation, correlation: presentation.correlation,
            reference: presentation.reference, hostChallenge: presentation.challenge
        )
        // The create-once marker precedes Apple key generation. If the app
        // stops before staging, restart denies rather than inventing a key.
        try storage.markPreparing(attemptID)
        let registration = try await appAttest.prepareRegistration(
            ceremonyID: presentation.ceremonyID, siteTrustDomain: presentation.site, clientDataHash: hash
        )
        guard nowMillis() < presentation.expiresAt else {
            throw PlatformFailure.siteRootGenesisPresentationExpired
        }
        let request = try SiteRootBrokerRegistrationWireV2.encode(
            presentation: presentation, operationID: operation,
            siteRootKey: siteRootKey, appAttest: registration.envelope
        )
        let pending = ScopedAppAttestPending(
            attemptID: attemptID, correlation: presentation.correlation,
            registrationReference: presentation.reference, siteClaim: presentation.site,
            appClaim: AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            environmentClaim: "Production", keyID: registration.keyID, preparedRegistration: request
        )
        try storage.stagePrepared(pending)
        return pending
    }
}
