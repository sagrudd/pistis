import Foundation

struct SiteOriginRelocationReview: Identifiable, Equatable {
    let id: Data
    let siteIdentity: String
    let sourceOrigin: String
    let targetOrigin: String
    let generations: String
    let warning: String
}

/// Keeps an approved submission in memory until Monas status removes network
/// ambiguity. It never asks Face ID twice or falls back to device enrolment.
@MainActor
final class SiteOriginRelocationCoordinator: ObservableObject {
    enum Phase: Equatable { case idle, review, approving, reconciling, completed, cancelled, failed }
    @Published private(set) var phase: Phase = .idle
    @Published private(set) var presentedReview: SiteOriginRelocationReview?
    private let authorityTransport: MonasSiteRootDelegationTransport?
    private let producer: SecureEnclaveSiteOriginRelocationProducerV1
    private var pending: SiteOriginRelocationPresentationV1?

    init(
        authorityTransport: MonasSiteRootDelegationTransport?,
        producer: SecureEnclaveSiteOriginRelocationProducerV1 = .init()
    ) {
        self.authorityTransport = authorityTransport
        self.producer = producer
    }

    func accept(qrText: String, nowUnixSeconds: UInt64 = UInt64(Date().timeIntervalSince1970)) {
        do {
            let value = try SiteOriginRelocationPresentationV1(
                qrText: qrText, nowUnixSeconds: nowUnixSeconds
            )
            pending = value
            presentedReview = SiteOriginRelocationReview(
                id: value.proposalDigest,
                siteIdentity: "\(value.siteTrustDomain) · \(value.siteUUID.hex)",
                sourceOrigin: value.sourceOrigin.absoluteString,
                targetOrigin: value.targetOrigin.absoluteString,
                generations: "Origin \(value.sourceGeneration) → \(value.proposedGeneration); authority \(value.authorityGeneration); custody \(value.custodyGeneration); root \(value.siteRootGeneration); issuer \(value.issuingCAGeneration)",
                warning: SiteOriginRelocationProfileV1.warning
            )
            phase = .review
        } catch {
            pending = nil; presentedReview = nil; phase = .failed
        }
    }

    func approve() async {
        guard let pending, let authorityTransport else { phase = .failed; return }
        do {
            let transport = try authorityTransport.siteOriginRelocationTransport(
                targetOrigin: pending.targetOrigin
            )
            phase = .approving
            let submission = try await producer.produce(pending)
            phase = .reconciling
            let status = try await transport.submit(submission, expected: pending)
            guard status.state == .approved || status.state == .certificateReady
                    || status.state == .committed || status.state == .converged
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
            phase = .completed
        } catch { phase = .failed }
    }

    func cancel() async {
        guard let pending, let authorityTransport else { reset(); return }
        do {
            let transport = try authorityTransport.siteOriginRelocationTransport(
                targetOrigin: pending.targetOrigin
            )
            _ = try await transport.cancel(pending)
            phase = .cancelled
        } catch { phase = .failed }
    }

    func reset() { pending = nil; presentedReview = nil; phase = .idle }
}

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
