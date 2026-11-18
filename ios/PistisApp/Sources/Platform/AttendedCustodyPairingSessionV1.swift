import CryptoKit
import Foundation
import Security
import UIKit

enum AttendedCustodyPairingErrorV1: Error { case denied, unconfirmed }

/// One attended recovery over the paired channel. A failure after the
/// challenge is returned is uncertain and must never trigger an automatic retry.
@MainActor
final class AttendedCustodyPairingSessionV1 {
    let sas: String
    private let offer: AttendedCustodyPairingOfferV1
    private let enrollment: AuthenticatedEnrollmentOutput
    private let binding: ScopedAppAttestBinding
    private let signer: SecureEnclaveSigner
    private let connection: AttendedCustodyPairingConnectionV1
    private let exchange: AttendedCustodyPairingExchangeV1
    private let deadline: ContinuousClock.Instant
    private let transcriptDigest: Data
    private var consumed = false

    private init(offer: AttendedCustodyPairingOfferV1, enrollment: AuthenticatedEnrollmentOutput,
                 binding: ScopedAppAttestBinding, signer: SecureEnclaveSigner,
                 connection: AttendedCustodyPairingConnectionV1,
                 exchange: AttendedCustodyPairingExchangeV1, deadline: ContinuousClock.Instant, transcriptDigest: Data, sas: String) {
        self.offer = offer; self.enrollment = enrollment; self.binding = binding; self.signer = signer
        self.connection = connection; self.exchange = exchange; self.deadline = deadline
        self.transcriptDigest = transcriptDigest; self.sas = sas
    }

    static func prepare(qrText: String) async throws -> AttendedCustodyPairingSessionV1 {
        let sampled = ContinuousClock().now
        let wall = Date().timeIntervalSince1970
        guard wall.isFinite, wall >= 0, wall < Double(UInt64.max),
              let enrollment = try await InstallationTrustKeychain.shared.activeEnrollment() else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let now = UInt64(wall)
        let offer = try AttendedCustodyPairingOfferV1(qrText: qrText, now: now)
        guard let binding = try ScopedAppAttestStore().binding(installationID: offer.installation) else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let signer = try SecureEnclaveSigner(namespace: IssuerNativeSessionWire.hex(offer.installation),
            authenticationReason: "Verify the enrolled device for custody recovery")
        guard try signer.hasExistingKey() else { throw PlatformFailure.custodyRewrapUnavailable }
        let point = try signer.publicKey().compressedSEC1
        try validateAttendedCustodyPairingOwnerV1(offer: offer, enrollment: enrollment,
            binding: binding, devicePoint: point, now: Date())
        let remaining = offer.expiresAt - now
        // `now` was truncated to whole seconds. Subtract one second so the
        // monotonic deadline cannot extend the original wall-clock expiry.
        guard remaining > 1 else { throw PlatformFailure.custodyRewrapUnavailable }
        let deadline = sampled.advanced(by: .seconds(Int64(remaining - 1)))
        guard ContinuousClock().now < deadline else { throw PlatformFailure.custodyRewrapUnavailable }
        let ephemeral = AttendedCustodyPairingEphemeralV1()
        var nonce = Data(count: 32)
        let randomStatus = nonce.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard randomStatus == errSecSuccess, nonce.contains(where: { $0 != 0 }) else { throw PlatformFailure.custodyRewrapUnavailable }
        let transcript = AttendedCustodyPairingTranscriptV1(session: offer.session, installation: offer.installation,
            installationKeySHA256: offer.installationKeySHA256, deviceID: offer.deviceID,
            devicePublic: offer.devicePublic, hostPublic: offer.hostPublic, phonePublic: ephemeral.publicKey,
            hostNonce: offer.hostNonce, phoneNonce: nonce, issuedAt: offer.issuedAt,
            expiresAt: offer.expiresAt, siteDomain: offer.siteDomain)
        let keys = try ephemeral.derive(peerPublic: offer.hostPublic, transcript: transcript, localIsHost: false, now: now)
        let sas = keys.shortAuthenticationString
        let exchange = try AttendedCustodyPairingExchangeV1(keys: keys, deadline: deadline)
        let connection = try AttendedCustodyPairingConnectionV1(offer: offer, deadline: deadline)
        try await connection.start()
        try await connection.send(Data("MPH1".utf8) + ephemeral.publicKey + nonce)
        return Self(offer: offer, enrollment: enrollment, binding: binding, signer: signer,
                    connection: connection, exchange: exchange, deadline: deadline,
                    transcriptDigest: try transcript.digest(now: now), sas: sas)
    }

    func cancel() { connection.cancel() }

    private func unixNow() throws -> UInt64 {
        let value = Date().timeIntervalSince1970
        guard value.isFinite, value >= 0, value < Double(UInt64.max) else { throw PlatformFailure.custodyRewrapUnavailable }
        return UInt64(value)
    }

    private func checkOwner() async throws {
        try Task.checkCancellation()
        let wall = Date().timeIntervalSince1970
        guard UIApplication.shared.applicationState == .active, ContinuousClock().now < deadline,
              wall.isFinite, wall >= Double(offer.issuedAt), wall < Double(offer.expiresAt),
              try await InstallationTrustKeychain.shared.activeEnrollment() == enrollment,
              try ScopedAppAttestStore().binding(installationID: offer.installation) == binding,
              try signer.hasExistingKey() else { throw PlatformFailure.custodyRewrapUnavailable }
        try validateAttendedCustodyPairingOwnerV1(offer: offer, enrollment: enrollment,
            binding: binding, devicePoint: try signer.publicKey().compressedSEC1, now: Date())
    }

    private func claim() throws {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
            kSecAttrService: "org.mnemosyne.pistis.attended-custody-pairing.v1",
            kSecAttrAccount: offer.session.base64EncodedString(),
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData: transcriptDigest]
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else { throw PlatformFailure.custodyRewrapUnavailable }
    }

    private func request(_ kind: UInt8, _ body: Data = Data()) async throws -> (UInt16, Data) {
        try await checkOwner()
        let outgoing = try exchange.request(kind: kind, payload: body)
        try await connection.sendRecord(outgoing)
        let incoming = try await connection.receiveRecord()
        let (responseKind, payload) = try exchange.receive(incoming)
        try await checkOwner()
        guard responseKind == kind, payload.count >= 2 else { throw PlatformFailure.custodyRewrapUnavailable }
        let code = payload.prefix(2).reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
        return (code, Data(payload.dropFirst(2)))
    }

    /// Called only after the owner explicitly confirms the same displayed SAS
    /// on this phone and on the authenticated operator terminal.
    func approveAndRecover() async throws {
        guard !consumed else { throw PlatformFailure.custodyRewrapUnavailable }
        consumed = true
        var sensitive = false
        do {
            try await checkOwner(); try claim()
            let confirmation = try exchange.localConfirmation()
            try await connection.sendRecord(confirmation)
            let incoming = try await connection.receiveRecord()
            let (kind, _) = try exchange.receive(incoming)
            guard kind == 0 else { throw PlatformFailure.custodyRewrapUnavailable }
            let (initialCode, initialBody) = try await request(1)
            guard initialCode == 503, initialBody.isEmpty else { throw PlatformFailure.custodyRewrapUnavailable }
            sensitive = true // Host must persist its fence before returning this challenge.
            let (challengeCode, challengeBody) = try await request(2)
            guard challengeCode == 200 else { throw PlatformFailure.custodyRewrapUnavailable }
            let now = try unixNow()
            let challenge = try CustodyRotationAppAttestChallengeV2(data: challengeBody, nowUnixSeconds: now)
            guard challenge.installationID == offer.installation else { throw PlatformFailure.custodyRewrapUnavailable }
            let assertion = try await AppleAppAttestClient().prepareSelectedCustodyRotationAssertion(challenge: challenge)
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let (assertionCode, assertionBody) = try await request(3, encoder.encode(assertion.envelope))
            guard assertionCode == 202, assertionBody.isEmpty else { throw PlatformFailure.custodyRewrapUnavailable }
            let (statusCode, statusBody) = try await request(4)
            guard statusCode == 200, let status = try JSONSerialization.jsonObject(with: statusBody) as? [String: String],
                  Set(status.keys) == ["schema", "state"], status["schema"] == "monas.first-authority-custody-status.v2",
                  status["state"] == "recovery-required" else { throw PlatformFailure.custodyRewrapUnavailable }
            let store = try KeychainFirstAuthorityRecoveryEnvelopeStore(site: binding.site, attemptID: binding.attemptID)
            let producer = try SecureEnclaveFirstAuthorityCustodyProducerV2(authenticationReason: "Recover the existing authority custody", store: store)
            let commitment = try producer.retainedRecoveryCommitment()
            let (beginCode, beginBody) = try await request(5, encoder.encode(FirstAuthorityCustodyRotationV2Wire.RecoveryBegin()))
            guard beginCode == 200 else { throw PlatformFailure.custodyRewrapUnavailable }
            let presentation = try FirstAuthorityCustodyRotationV2Wire.recoveryPresentation(data: beginBody,
                expectedDeviceKeyID: commitment.deviceKeyID, expectedEnrolledPublicKey: commitment.enrolledDevicePublicSEC1,
                expectedRecoveryCommitment: commitment.recoverySeedEd25519PublicKey, nowUnixSeconds: try unixNow())
            guard presentation.identity.siteTrustDomain == offer.siteDomain else { throw PlatformFailure.custodyRewrapUnavailable }
            try await checkOwner()
            let submission = try producer.completeRecovery(presentation)
            let (completeCode, completeBody) = try await request(6, encoder.encode(FirstAuthorityCustodyRotationV2Wire.RecoveryComplete(submission)))
            guard completeCode == 200 else { throw PlatformFailure.custodyRewrapUnavailable }
            _ = try FirstAuthorityCustodyRotationV2Wire.accepted(data: completeBody,
                expectedCorrelation: submission.correlation, schema: FirstAuthorityCustodyRotationV2Wire.recoveryAcceptedSchema)
            try await checkOwner()
            let (receiptCode, receiptBody) = try await request(7, Data(SHA256.hash(data: completeBody)))
            guard receiptCode == 200, receiptBody.isEmpty else { throw PlatformFailure.custodyRewrapUnavailable }
            try await checkOwner(); connection.cancel()
        } catch { connection.cancel(); throw sensitive ? AttendedCustodyPairingErrorV1.unconfirmed : AttendedCustodyPairingErrorV1.denied }
    }
}
