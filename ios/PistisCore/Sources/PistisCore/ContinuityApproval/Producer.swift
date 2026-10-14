import Crypto
import Foundation

// Adapter contracts stay module-internal until the independent current-credential
// proof/ingress profile is supplied and reviewed. Test models cannot be installed
// through a public accepted-context factory or a deserialised trusted token.
protocol ContinuityCurrentAuthority: Sendable {
    func revalidate(_ kind: ContinuityApprovalKind, presentation: ValidatedContinuityPresentation,
                    exactBodyDigest: Data) async throws
}
protocol ContinuityPhoneDriver: Sendable {
    func attestDescriptor(_ presentation: ValidatedContinuityPresentation) async throws -> Data
    func selectContinuityMode(_ presentation: ValidatedContinuityPresentation,
                              selection: ContinuityValue) async throws -> Data
    func attestIssuer(_ presentation: ValidatedContinuityPresentation,
                      issuer: ContinuityValue) async throws -> Data
}
protocol ContinuityApprovalClock: Sendable { func seconds() throws -> UInt64 }

/// Closed source producer. Its public/default configuration fails closed:
/// genuine current purpose enrolment/revocation and protected ledger adapters
/// have not yet been supplied. No existing Site credential is repurposed.
public actor ContinuityApprovalProducer {
    private let authority: any ContinuityCurrentAuthority
    private let driver: any ContinuityPhoneDriver
    private let ledger: any ContinuityApprovalLedger
    private let clock: any ContinuityApprovalClock

    public init() {
        authority = UnavailableContinuityBridge(); driver = UnavailableContinuityBridge()
        ledger = UnavailableContinuityLedger(); clock = ContinuityWallClock()
    }
    init(authority: any ContinuityCurrentAuthority, driver: any ContinuityPhoneDriver,
         ledger: any ContinuityApprovalLedger, clock: any ContinuityApprovalClock) {
        self.authority = authority; self.driver = driver; self.ledger = ledger; self.clock = clock
    }

    /// Attest only the exact immutable descriptor after independent fresh approval.
    public func attestDescriptor(_ presentation: ValidatedContinuityPresentation) async throws -> Data {
        try await execute(.descriptor, presentation: presentation, body: presentation.descriptor.value, selectionInterval: nil)
    }

    /// Select only exact PCMS after a retained verified descriptor; no issuer approval yet.
    public func selectContinuityMode(_ presentation: ValidatedContinuityPresentation,
                                     canonicalSelection: Data) async throws -> Data {
        let descriptor = try await retained(.descriptor, presentation: presentation)
        let body = try presentation.selectionBody(canonicalSelection, signedDescriptor: descriptor)
        let fields = try body.fields(18)
        let selectionInterval = try ContinuityInterval(fields[16], fields[17])
        guard selectionInterval.current(try clock.seconds()) else {
            throw ContinuityApprovalError.expired
        }
        return try await execute(.selection, presentation: presentation, body: body, selectionInterval: selectionInterval)
    }

    /// Construct unchanged PCII solely from the exact allocation and independently
    /// verified retained PCMS. No arbitrary issuer payload or legacy consent is accepted.
    public func attestIssuer(_ presentation: ValidatedContinuityPresentation) async throws -> Data {
        let descriptor = try await retained(.descriptor, presentation: presentation)
        let selection = try await retained(.selection, presentation: presentation)
        _ = try presentation.verifySelection(selection, signedDescriptor: descriptor)
        let fields = try ContinuitySignedEnvelope(selection, kind: .selection,
            publicKey: presentation.approvalPublicKey).body.fields(18)
        let selectionInterval = try ContinuityInterval(fields[16], fields[17])
        guard selectionInterval.current(try clock.seconds()) else {
            throw ContinuityApprovalError.expired
        }
        return try await execute(.issuer, presentation: presentation,
                                 body: presentation.issuerBody(signedDescriptor: descriptor),
                                 selectionInterval: selectionInterval)
    }

    private func retained(_ kind: ContinuityApprovalKind,
                          presentation: ValidatedContinuityPresentation) async throws -> Data {
        let identity = ContinuityOperationIdentity(operation: presentation.allocation.operation, kind: kind)
        guard let record = try await ledger.read(identity), record.phase == .signedRetained,
              let envelope = record.envelope else { throw ContinuityApprovalError.invalidOrder }
        // Storage is not trusted by decoding it; verify complete retained signature.
        let checked = try ContinuitySignedEnvelope(envelope, kind: kind,
                                                  publicKey: presentation.approvalPublicKey)
        guard checked.body.encoded == record.body else { throw ContinuityApprovalError.conflict }
        if kind == .descriptor { _ = try presentation.descriptorEnvelope(envelope) }
        return envelope
    }

    private func execute(_ kind: ContinuityApprovalKind,
                         presentation: ValidatedContinuityPresentation,
                         body: ContinuityValue, selectionInterval: ContinuityInterval?) async throws -> Data {
        let raw = body.encoded, bodyDigest = Data(SHA256.hash(data: raw))
        // Covers current independent credential/purpose/lifecycle/revocation,
        // complete generation provenance, excluded keys, attended authentication,
        // exact request ingress and monotonic floor. Public tuple facts cannot do this.
        try Task.checkCancellation()
        try await authority.revalidate(kind, presentation: presentation, exactBodyDigest: bodyDigest)
        let now = try clock.seconds()
        guard presentation.current(now), selectionInterval?.current(now) != false else {
            throw ContinuityApprovalError.expired
        }
        let identity = ContinuityOperationIdentity(operation: presentation.allocation.operation, kind: kind)
        let existing = try await ledger.reserve(identity, exactBody: raw)
        guard existing.identity == identity, existing.body == raw else { throw ContinuityApprovalError.conflict }
        switch existing.phase {
        case .signedRetained:
            guard let bytes = existing.envelope else { throw ContinuityApprovalError.retentionFailure }
            let signed = try ContinuitySignedEnvelope(bytes, kind: kind, publicKey: presentation.approvalPublicKey)
            guard signed.body == body else { throw ContinuityApprovalError.conflict }
            return bytes // Read-only exact retrieval; never signs or changes immutable bytes.
        case .dispatchFenced, .unresolved: throw ContinuityApprovalError.ambiguousInvocation
        case .terminalProvenUnsigned: throw ContinuityApprovalError.invalidOrder
        case .preparedNoKeyInvocation: break
        }
        try await ledger.fence(identity, exactBody: raw)
        do {
            try await authority.revalidate(kind, presentation: presentation, exactBodyDigest: bodyDigest)
            let now = try clock.seconds()
            guard presentation.current(now), selectionInterval?.current(now) != false else {
                throw ContinuityApprovalError.expired
            }
            try Task.checkCancellation()
        } catch {
            // The driver has not been called. Only this serial, exact durable
            // fence transition can record never-invoked; a timeout cannot.
            try await ledger.neverInvoked(identity, exactBody: raw)
            throw error
        }
        do {
            let signature: Data
            switch kind {
            case .descriptor: signature = try await driver.attestDescriptor(presentation)
            case .selection: signature = try await driver.selectContinuityMode(presentation, selection: body)
            case .issuer: signature = try await driver.attestIssuer(presentation, issuer: body)
            }
            let bytes = ContinuityValue.array([body, .bytes(presentation.descriptor.approvalKeyID),
                                                .bytes(signature)]).encoded
            let checked = try ContinuitySignedEnvelope(bytes, kind: kind, publicKey: presentation.approvalPublicKey)
            guard checked.body == body else { throw ContinuityApprovalError.signature }
            try await ledger.retain(identity, exactBody: raw, envelope: bytes)
            return bytes
        } catch {
            // Possibly invoked, including invalid result or failed retention:
            // preserve ambiguity. Never retry private operation automatically.
            try? await ledger.unresolved(identity, exactBody: raw)
            throw ContinuityApprovalError.ambiguousInvocation
        }
    }
}

private struct UnavailableContinuityBridge: ContinuityCurrentAuthority, ContinuityPhoneDriver {
    func revalidate(_ kind: ContinuityApprovalKind, presentation: ValidatedContinuityPresentation,
                    exactBodyDigest: Data) async throws { throw ContinuityApprovalError.unavailableEnrollment }
    func attestDescriptor(_ presentation: ValidatedContinuityPresentation) async throws -> Data {
        throw ContinuityApprovalError.unavailableAuthority
    }
    func selectContinuityMode(_ presentation: ValidatedContinuityPresentation,
                              selection: ContinuityValue) async throws -> Data { throw ContinuityApprovalError.unavailableAuthority }
    func attestIssuer(_ presentation: ValidatedContinuityPresentation,
                      issuer: ContinuityValue) async throws -> Data { throw ContinuityApprovalError.unavailableAuthority }
}
private struct ContinuityWallClock: ContinuityApprovalClock {
    func seconds() throws -> UInt64 {
        let value = Date().timeIntervalSince1970
        guard value.isFinite, value >= 0, value < Double(UInt64.max) else { throw ContinuityApprovalError.expired }
        return UInt64(value)
    }
}
