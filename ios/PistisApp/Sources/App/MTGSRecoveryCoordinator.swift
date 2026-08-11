import Foundation

struct MTGSRecoveryReview: Equatable, Identifiable {
    var id: String { reference + destination }
    let reference: String
    let siteTrustDomain: String
    let destination: String

    init(_ presentation: MTGSRecoveryPresentationV1) {
        reference = Self.redact(presentation.reference)
        siteTrustDomain = presentation.siteTrustDomain
        destination = presentation.authorityOrigin.host ?? "unavailable"
    }

    private static func redact(_ value: String) -> String {
        guard value.count > 12 else { return "redacted" }
        return "\(value.prefix(6))…\(value.suffix(4))"
    }
}

@MainActor
final class MTGSRecoveryCoordinator: ObservableObject {
    enum Phase: Equatable {
        case idle
        case review(MTGSRecoveryReview)
        case attending
        case submitted
        case failed(PlatformFailure)
    }

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var presentedReview: MTGSRecoveryReview?
    private let authorityOrigin: URL?
    private let service: any MTGSRecoveryExecuting
    private let history: (HistoryEvent) throws -> Void
    private var pending: MTGSRecoveryPresentationV1?

    init(
        authorityOrigin: URL?,
        service: any MTGSRecoveryExecuting,
        history: @escaping (HistoryEvent) throws -> Void = {
            try LocalHistoryRepository.shared.record($0)
        }
    ) {
        self.authorityOrigin = authorityOrigin
        self.service = service
        self.history = history
    }

    func accept(qrText: String, nowUnixSeconds: UInt64? = nil) {
        do {
            guard let authorityOrigin else { throw PlatformFailure.siteRootAuthorityUnavailable }
            let now = try (nowUnixSeconds ?? Self.now())
            let presentation = try MTGSRecoveryPresentationV1(
                qrText: qrText, pinnedAuthorityOrigin: authorityOrigin, nowUnixSeconds: now
            )
            pending = presentation
            let review = MTGSRecoveryReview(presentation)
            presentedReview = review
            phase = .review(review)
        } catch let failure as PlatformFailure {
            record(failure: failure)
            phase = .failed(failure)
        } catch {
            record(failure: .qrPayloadUnsupported)
            phase = .failed(.qrPayloadUnsupported)
        }
    }

    func approve() async {
        guard let pending else {
            record(failure: .invalidConfiguration)
            phase = .failed(.invalidConfiguration)
            return
        }
        phase = .attending
        do {
            try await service.execute(pending)
            recordSuccess()
            phase = .submitted
        } catch let failure as PlatformFailure {
            record(failure: failure)
            phase = .failed(failure)
        } catch {
            record(failure: .productionEnvelopeUnavailable)
            phase = .failed(.productionEnvelopeUnavailable)
        }
    }

    func reset() {
        pending = nil
        presentedReview = nil
        phase = .idle
    }

    private func recordSuccess() {
        try? history(event(
            decision: "Verified",
            signature: "Fresh Face ID and Apple App Attest assertion accepted",
            transfer: "Submitted once to fixed Monas MTGS recovery authority",
            verification: "Monas retained the one-shot recovery dispatch envelope"
        ))
    }

    private func record(failure: PlatformFailure) {
        try? history(event(
            decision: "Not completed",
            signature: "No recovery assertion retained",
            transfer: "Recovery dispatch was not confirmed",
            verification: failure.safeUserMessage
        ))
    }

    private func event(
        decision: String, signature: String, transfer: String, verification: String
    ) -> HistoryEvent {
        HistoryEvent(
            id: UUID(), action: "Site Trust MTGS recovery",
            installation: presentedReview?.destination ?? "Monas Site Trust authority",
            occurredAt: Date().formatted(date: .abbreviated, time: .standard),
            decision: decision, signature: signature, transfer: transfer,
            verification: verification
        )
    }

    private static func now() throws -> UInt64 {
        let value = Date().timeIntervalSince1970
        guard value.isFinite, value >= 0, value <= Double(UInt64.max) else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
        return UInt64(value)
    }
}
