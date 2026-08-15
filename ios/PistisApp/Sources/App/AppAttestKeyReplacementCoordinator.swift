import Foundation

struct AppAttestKeyReplacementReviewV1: Identifiable, Equatable {
    let id: Data
    let site: String
    let device: String
    let currentKey: String
    let authority: String
    let expiry: String
}

protocol AppAttestKeyReplacementCommittingV1: Sendable {
    func commitReplacementKey(
        _ pending: PendingAppAttestReplacementKeyV1,
        authenticated: AuthenticatedAppAttestReplacementAcceptanceV1
    ) throws
    func discardReplacementKey(transactionUUID: Data) throws
}

extension AppleAppAttestClient: AppAttestKeyReplacementCommittingV1 {}

@MainActor
final class AppAttestKeyReplacementCoordinatorV1: ObservableObject {
    enum Phase: Equatable {
        case idle
        case review
        case producing
        case responseReady
        case submitting
        case accepted
        case failed
    }

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var presentedReview: AppAttestKeyReplacementReviewV1?
    @Published private(set) var responseFileBytes: Data?
    private let producer: any AppAttestKeyReplacementProducingV1
    private let committer: any AppAttestKeyReplacementCommittingV1
    private var presentation: AppAttestKeyReplacementPresentationV1?
    private var staged: PendingAppAttestReplacementKeyV1?

    init(
        producer: any AppAttestKeyReplacementProducingV1 =
            SecureEnclaveAppAttestKeyReplacementProducerV1(),
        committer: any AppAttestKeyReplacementCommittingV1 = AppleAppAttestClient()
    ) {
        self.producer = producer
        self.committer = committer
    }

    func accept(
        qrText: String,
        nowUnixMillis: UInt64 = UInt64(Date().timeIntervalSince1970 * 1_000)
    ) {
        do {
            accept(
                try AppAttestKeyReplacementPresentationV1(
                    qrText: qrText, nowUnixMillis: nowUnixMillis
                ))
        } catch {
            reset()
            phase = .failed
        }
    }

    func accept(
        fileBytes: Data,
        nowUnixMillis: UInt64 = UInt64(Date().timeIntervalSince1970 * 1_000)
    ) {
        do {
            accept(
                try AppAttestKeyReplacementPresentationV1(
                    fileBytes: fileBytes, nowUnixMillis: nowUnixMillis
                ))
        } catch {
            reset()
            phase = .failed
        }
    }

    func approve(
        nowUnixMillis: UInt64 = UInt64(Date().timeIntervalSince1970 * 1_000)
    ) async {
        guard let presentation else {
            phase = .failed
            return
        }
        do {
            phase = .producing
            let response = try await producer.produce(
                presentation, nowUnixMillis: nowUnixMillis
            )
            guard response.pendingKey.transactionUUID == presentation.transactionUUID,
                response.pendingKey.expectedCurrentKeyID
                    == presentation.oldKeyID.base64EncodedString(),
                !response.canonicalResponse.isEmpty,
                response.canonicalResponse.count
                    <= AppAttestKeyReplacementOfflineProfileV1.maximumJSONBytes
            else { throw PlatformFailure.appAttestInvalidInput }
            staged = response.pendingKey
            responseFileBytes = response.canonicalResponse
            phase = .responseReady
        } catch {
            responseFileBytes = nil
            phase = .failed
        }
    }

    /// Only the opaque capability returned by the fixed, pinned Monas
    /// transport can promote the Keychain primary key. Raw files and caller-
    /// constructed JSON are not an acceptance boundary.
    func commitAuthenticatedAccepted(
        _ authenticated: AuthenticatedAppAttestReplacementAcceptanceV1
    ) {
        do {
            let accepted = authenticated.accepted
            guard phase == .responseReady, let staged, let presentation,
                PXARJSON.canonicalUUID(accepted.transactionID) == staged.transactionUUID,
                accepted.installationID == presentation.wire.installationID,
                accepted.oldGeneration == presentation.wire.oldGeneration,
                accepted.newGeneration == presentation.wire.newGeneration,
                accepted.oldKeyIDB64URL == presentation.wire.oldKeyIDB64URL,
                let newKey = PXARJSON.base64URL(accepted.newKeyIDB64URL, count: 32),
                newKey.base64EncodedString() == staged.replacementKeyID
            else { throw PlatformFailure.appAttestInvalidInput }
            try committer.commitReplacementKey(staged, authenticated: authenticated)
            responseFileBytes = nil
            phase = .accepted
        } catch { phase = .failed }
    }

    func submitAndCommit(using transport: MonasAppAttestTransport) async {
        guard phase == .responseReady, let responseFileBytes else {
            phase = .failed
            return
        }
        do {
            phase = .submitting
            let authenticated = try await transport.submitAppAttestReplacement(
                canonicalSubmission: responseFileBytes
            )
            // Restore the guarded phase consumed by the same commit boundary.
            phase = .responseReady
            commitAuthenticatedAccepted(authenticated)
        } catch {
            phase = .failed
        }
    }

    func discard() {
        guard let transaction = staged?.transactionUUID ?? presentation?.transactionUUID else {
            reset()
            return
        }
        do {
            try committer.discardReplacementKey(transactionUUID: transaction)
            reset()
        } catch { phase = .failed }
    }

    func reset() {
        presentation = nil
        staged = nil
        presentedReview = nil
        responseFileBytes = nil
        phase = .idle
    }

    private func accept(_ value: AppAttestKeyReplacementPresentationV1) {
        presentation = value
        presentedReview = AppAttestKeyReplacementReviewV1(
            id: value.digest,
            site: value.wire.siteTrustDomain,
            device: "\(value.wire.installationID) · \(value.wire.deviceID)",
            currentKey: value.oldKeyID.map { String(format: "%02x", $0) }.joined(),
            authority: "App Attest generation \(value.wire.oldGeneration) → \(value.wire.newGeneration)",
            expiry: Date(
                timeIntervalSince1970: TimeInterval(value.wire.expiresAtUnixMillis) / 1_000
            ).formatted()
        )
        phase = .review
    }
}
