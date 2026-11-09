import CryptoKit
import Foundation
import PistisCore

/// Inactive pinned status exchange. A returned binding still needs the reviewed
/// durable promotion sequence; it never installs or selects an enrollment.
struct FirstDeviceStatusClientV2 {
    private let session: URLSession
    private let presentation: VerifiedFirstDevicePresentation

    init(presentation: VerifiedFirstDevicePresentation) throws {
        self.presentation = presentation
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = URLSession(configuration: configuration,
            delegate: try PinnedEnrolmentSessionDelegate(origin: presentation.httpsOrigin,
                expectedSPKISHA256: presentation.tlsSPKISHA256), delegateQueue: nil)
    }

    func verify(attemptID: UUID, storage: ScopedAppAttestStore,
                nowSeconds: @Sendable () -> UInt64) async throws -> ScopedAppAttestBinding {
        guard let pending = try storage.statusPending(attemptID: attemptID),
              let provisional = try storage.provisionalPresentation(attemptID: attemptID),
              let staged = try storage.stagedEnrollment(attemptID: attemptID),
              provisional.installationID == presentation.installationID,
              provisional.presentationDigest == presentation.presentationDigest,
              staged.output.trust.installationID == presentation.installationID,
              staged.output.httpsOrigin == presentation.httpsOrigin.absoluteString,
              staged.output.tlsSPKISHA256 == presentation.tlsSPKISHA256,
              let appleKey = PendingAppAttestReplacementKeyV1.canonicalKeyID(pending.keyID)
        else { throw PlatformFailure.invalidConfiguration }
        let recovered = try ProvisionalPresentationRecovery.verify(provisional,
            expectedAppConfigurationDigest: GitHubEnrolmentConfiguration.reviewedAppConfigurationDigest)
        guard recovered == presentation else { throw PlatformFailure.invalidConfiguration }
        let root = try SecureEnclaveSiteRootProofProducer(authenticationReason: "Confirm this Monas Site Root")
        guard let registration = try root.existingRegistration() else { throw PlatformFailure.keyNotFound }
        let request = try StrictJSONObject(data: pending.preparedRegistration, maximumBytes: 12 * 1024).values
        guard case let .object(key)? = request["site_root_key"],
              key["device_key_id"] == .string(registration.deviceKeyID),
              key["public_key_compressed_sec1_base64url"] == .string(SiteRootBrokerPresentationV2.encode(registration.publicKeyCompressedSEC1))
        else { throw PlatformFailure.invalidConfiguration }
        let namespace = presentation.installationID.map { String(format: "%02x", $0) }.joined()
        let deviceSigner = try SecureEnclaveSigner(namespace: namespace, authenticationReason: "Confirm this Pistis installation")
        let deviceKey = try deviceSigner.publicKey().compressedSEC1
        guard Data(SHA256.hash(data: Data("pistis:key-id:v1\0".utf8) + deviceKey)) == staged.output.responseContext.deviceKeyID
        else { throw PlatformFailure.invalidConfiguration }
        var uuid = attemptID.uuid
        let operation = withUnsafeBytes(of: &uuid) { Data($0) }
        let encode = SiteRootBrokerPresentationV2.encode
        let base: [String: Any] = ["operation_b64url": encode(operation), "reference": pending.registrationReference]
        var challengeRequest = base
        challengeRequest["schema"] = "monas.first-device.status.challenge-request.v2"
        try storage.beginSubmittedPoll(attemptID: attemptID, expected: pending)
        defer { storage.endDispatch() }
        let challengeData = try await post(path: "/auth/pistis/v2/first-device-status/challenge", json: challengeRequest)
        let challenge = try FirstDeviceStatusResponseV2.challenge(challengeData, now: nowSeconds())
        let correlation = Data(SHA256.hash(data: Data("mnemosyne.monas.first-device.correlation.v2\0".utf8) + pending.correlation))
        let transcript = FirstDeviceStatusTranscriptV2(nonce: challenge.nonce, operationID: operation,
            correlationDigest: correlation, reference: pending.registrationReference,
            installationID: presentation.installationID, site: pending.siteClaim,
            presentationDigest: presentation.presentationDigest,
            receiptDigest: Data(SHA256.hash(data: staged.output.trust.authorityReceipt)),
            tlsSPKIDigest: presentation.tlsSPKISHA256, appAttestKeyID: appleKey,
            siteRootKeyDigest: Data(SHA256.hash(data: registration.publicKeyCompressedSEC1)),
            deviceKeyDigest: Data(SHA256.hash(data: deviceKey)), expiry: challenge.expiry)
        let rootSignature = try root.signFirstDeviceStatus(transcript)
        let deviceSignature = try FirstDeviceStatusProofV2.signDevice(transcript: transcript)
        guard nowSeconds() < challenge.expiry else { throw PlatformFailure.invalidConfiguration }
        var confirm = base
        confirm["schema"] = "monas.first-device.status.confirm-request.v2"
        confirm["nonce_b64url"] = encode(challenge.nonce)
        confirm["site_signature_b64url"] = encode(rootSignature)
        confirm["device_signature_b64url"] = encode(deviceSignature)
        let response = try await post(path: "/auth/pistis/v2/first-device-status/confirm", json: confirm)
        try FirstDeviceStatusResponseV2.validate(response, transcript: transcript,
            appIdentifier: pending.appClaim, environment: pending.environmentClaim,
            policyGeneration: staged.output.trust.policyGeneration,
            revocationGeneration: staged.output.trust.revocationGeneration)
        return ScopedAppAttestBinding(attemptID: attemptID, installationID: presentation.installationID,
            site: pending.siteClaim, appIdentifier: pending.appClaim, environment: pending.environmentClaim,
            keyID: pending.keyID, policyGeneration: staged.output.trust.policyGeneration,
            revocationGeneration: staged.output.trust.revocationGeneration)
    }

    private func post(path: String, json: [String: Any]) async throws -> Data {
        guard let url = URL(string: path, relativeTo: presentation.httpsOrigin)?.absoluteURL,
              url.scheme == "https", url.host == presentation.httpsOrigin.host,
              url.port == presentation.httpsOrigin.port else { throw PlatformFailure.invalidConfiguration }
        let body = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys])
        guard body.count <= 4_096 else { throw PlatformFailure.invalidConfiguration }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"; request.httpBody = body; request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        let (data, raw) = try await session.data(for: request)
        guard let response = raw as? HTTPURLResponse, response.url == url,
              response.statusCode == 200, response.value(forHTTPHeaderField: "Set-Cookie") == nil,
              response.value(forHTTPHeaderField: "Cache-Control")?.lowercased().contains("no-store") == true,
              data.count <= 4_096 else { throw PlatformFailure.siteRootAuthorityUnavailable }
        return data
    }
}
