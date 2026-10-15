import Foundation

/// Pure sequencing and immutable DATA binding. This type supplies no signing authority.
public struct IssuerPhoneOperation: Sendable {
    private enum Phase: Sendable { case prepared, faceReady, armed, invoking(UInt64), preSigned, postSigned, terminal, locked }
    private let readiness: IssuerPhoneReadiness
    private let rootReference: Data?
    private let preparedAt: ContinuousClock.Instant
    private var faceAt: ContinuousClock.Instant?
    private var nativeEnd: ContinuousClock.Instant?
    private var phase: Phase = .prepared
    private var preBody: IssuerCheckpointBody?
    private var preEnvelope: Data?
    private var taskDigest: Data?
    private var signedTask: IssuerPhoneTask?
    private var completedEnvelope: Data?

    public init(readiness: IssuerPhoneReadiness, rootAdmissionReference: Data?, preparedAt: ContinuousClock.Instant) throws {
        guard (readiness.mode == .admission && rootAdmissionReference == nil)
                || (readiness.mode == .currentStatusPair && rootAdmissionReference?.count == 32) else { throw IssuerPhoneError.binding }
        self.readiness = readiness; rootReference = rootAdmissionReference; self.preparedAt = preparedAt
    }
    public mutating func faceAuthenticated(at now: ContinuousClock.Instant) throws {
        guard case .prepared = phase, now >= preparedAt, now < preparedAt.advanced(by: .seconds(30)) else {
            phase = .locked; throw IssuerPhoneError.expired
        }
        faceAt = now; phase = .faceReady
    }
    /// Must run before sending arm. The earlier phone bound is never renewed by a response.
    public mutating func arm(at now: ContinuousClock.Instant) throws {
        guard case .faceReady = phase, let faceAt, now >= faceAt,
              now <= faceAt.advanced(by: .milliseconds(250)), now < preparedAt.advanced(by: .seconds(30)) else {
            phase = .locked; throw IssuerPhoneError.expired
        }
        nativeEnd = now.advanced(by: .seconds(2)); phase = .armed
    }
    public func checkCurrent(at now: ContinuousClock.Instant) throws {
        guard let nativeEnd, now < nativeEnd else { throw IssuerPhoneError.expired }
        switch phase { case .locked, .terminal: throw IssuerPhoneError.order; default: break }
    }
    /// The immutable original phone bound, for network cancellation only.
    public var originalDeadline: ContinuousClock.Instant? { nativeEnd }

    /// Fence this task before any key invocation. Re-entry after ambiguity cannot sign again.
    public mutating func beginSignature(_ task: IssuerPhoneTask, at now: ContinuousClock.Instant) throws {
        do {
            try checkCurrent(at: now)
            guard task.ceremonyID == readiness.ceremonyID, task.readinessDigest == readiness.digest else { throw IssuerPhoneError.binding }
            try task.body.compare(to: readiness, rootAdmissionReference: rootReference)
            switch phase {
            case .armed:
                guard task.ordinal == 1, task.kind == (readiness.mode == .admission ? .admission : .pre) else { throw IssuerPhoneError.order }
            case .preSigned:
                guard readiness.mode == .currentStatusPair, task.kind == .post, task.ordinal == 2,
                      let preBody, let preEnvelope,
                      task.preEnvelopeReference == IssuerCheckpointEnvelope.reference(preEnvelope, kind: .currentStatus) else { throw IssuerPhoneError.order }
                // Actual protected read and independent IRSP linkage are server-owned.
                // Every common status fact is immutable across this one phone operation.
                for index in 1 ... 7 { guard task.body.fields[index] == preBody.fields[index] else { throw IssuerPhoneError.binding } }
                guard task.body.fields[8] != preBody.fields[8], task.body.fields[9] == preBody.fields[9],
                      try task.body.fields[10].uint() > preBody.fields[10].uint() else { throw IssuerPhoneError.binding }
            default: throw IssuerPhoneError.order
            }
            taskDigest = task.digest; signedTask = task; phase = .invoking(task.ordinal)
        } catch { phase = .locked; throw error }
    }
    public mutating func signatureCompleted(task: IssuerPhoneTask, envelope: Data, sitePublicKey: Data, at now: ContinuousClock.Instant) throws {
        do {
            try checkCurrent(at: now)
            guard case let .invoking(ordinal) = phase, ordinal == task.ordinal, taskDigest == task.digest else { throw IssuerPhoneError.order }
            guard IssuerPhoneWire.sha256(sitePublicKey) == readiness.siteKeyID else { throw IssuerPhoneError.binding }
            try IssuerCheckpointEnvelope.verify(envelope, body: task.body, sitePublicKey: sitePublicKey)
            completedEnvelope = envelope
            if task.kind == .pre { preBody = task.body; preEnvelope = envelope; phase = .preSigned }
            else { phase = .postSigned }
        } catch { phase = .locked; throw error }
    }
    public mutating func finish(_ terminal: Data, at now: ContinuousClock.Instant) throws {
        do {
            try checkCurrent(at: now)
            guard case .postSigned = phase else { throw IssuerPhoneError.order }
            try IssuerPhoneWire.terminal(terminal, ceremonyID: readiness.ceremonyID); phase = .terminal
            completedEnvelope = nil; signedTask = nil
        } catch { phase = .locked; throw error }
    }
    /// Exact retained DATA only; this never invokes the key or renews a bound.
    public func exactCompletedReply(for task: IssuerPhoneTask, at now: ContinuousClock.Instant) throws -> Data {
        try checkCurrent(at: now)
        guard signedTask == task, let completedEnvelope else { throw IssuerPhoneError.order }
        switch phase { case .preSigned, .postSigned: return completedEnvelope; default: throw IssuerPhoneError.order }
    }
    /// Cancellation, restart, backgrounding and any ambiguous invocation are terminal.
    public mutating func lock() { phase = .locked; completedEnvelope = nil; signedTask = nil; preEnvelope = nil }
}
