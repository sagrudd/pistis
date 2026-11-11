#if DEBUG
import Foundation

/// Synthetic integration seam, never compiled into Release. It does not make a
/// network request or assert that the host accepted a broker receipt.
@MainActor
final class AttendedRecoveryTestHarness {
    private let parsed: AttendedRecoveryQRV1
    private let storage: ScopedAppAttestStore
    private let confirmation: AttendedRecoveryConfirmation

    init(qr: Data, storage: ScopedAppAttestStore, now: UInt64) throws {
        let value = try AttendedRecoveryQRV1(data: qr, now: now, storage: storage)
        guard try storage.attendedRecoveryProof(attemptID: value.pending.attemptID) == nil
        else { throw PlatformFailure.invalidConfiguration }
        parsed = value; self.storage = storage
        confirmation = try AttendedRecoveryConfirmation(comparison: value.transcript.comparison(),
            expiry: value.transcript.expiry, now: now)
    }
    func confirm(comparison: Data, now: UInt64) throws { try confirmation.confirm(displayed: comparison, now: now) }
    func cancel() { confirmation.cancel() }

    func submit(now: @MainActor () -> UInt64,
                sign: @MainActor (AttendedRecoveryTranscriptV1) throws -> Data,
                assertB: @MainActor (AttendedRecoveryTranscriptV1, Data) async throws -> Data,
                send: @MainActor (URLRequest) async throws -> (Data, HTTPURLResponse)) async throws {
        try Task.checkCancellation()
        try confirmation.consume(now: now())
        try storage.beginSubmittedPoll(attemptID: parsed.pending.attemptID, expected: parsed.pending)
        defer { storage.endDispatch() }
        try storage.reserveAttendedRecoveryAssertion(attemptID: parsed.pending.attemptID, expected: parsed.pending)
        let signature = try sign(parsed.transcript)
        try Task.checkCancellation()
        try confirmation.requireConsumed(now: now())
        let assertion = try await assertB(parsed.transcript, signature)
        try Task.checkCancellation()
        try confirmation.requireConsumed(now: now())
        let proof = try AttendedRecoveryProofWireV1.encode(transcript: parsed.transcript,
            signature: signature, assertion: assertion)
        let record = ScopedAttendedRecoveryProof(attemptID: parsed.pending.attemptID,
            correlation: parsed.pending.correlation, transcriptDigest: try parsed.transcript.digest(),
            nonce: parsed.transcript.nonce, expiresAt: parsed.transcript.expiry,
            relaySecret: parsed.relaySecret, proof: proof, successorSecret: parsed.successorSecret,
            successorExpiry: parsed.successorExpiry, requestID: parsed.requestID, intentDigest: parsed.intentDigest)
        try storage.stageAttendedRecoveryProof(record)
        let request = try AttendedRecoveryMailboxV1.request(requestID: parsed.requestID,
            relaySecret: parsed.relaySecret, intentDigest: parsed.intentDigest, proof: proof)
        try Task.checkCancellation()
        try storage.beginAttendedRecoveryDispatch(expected: record, now: now())
        defer { storage.endDispatch() }
        try Task.checkCancellation()
        try confirmation.requireConsumed(now: now())
        let (body, response) = try await send(request)
        try AttendedRecoveryMailboxV1.validateReceipt(body, response: response)
    }
}
#endif
