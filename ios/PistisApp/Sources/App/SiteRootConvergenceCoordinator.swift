import Foundation

struct SiteRootConvergenceReview: Equatable, Identifiable {
    enum Kind: Equatable {
        case bundleReceiptProvision(generation: UInt64)
        case siteX509Provision(generation: UInt64)
        case acknowledgement(action: UnsignedSiteRootConvergenceAssertionV2.Action,
                             rootGeneration: UInt64, trustRevision: UInt64)
    }

    let id = UUID()
    let site: String
    let expiresAt: Date
    let kind: Kind
}

@MainActor
final class SiteRootConvergenceCoordinator: ObservableObject {
    enum Phase: Equatable {
        case idle
        case review(SiteRootConvergenceReview)
        case authenticating
        case unlockingBundleReceipt
        case submitting
        case completed
        case failed(PlatformFailure)
    }

    @Published private(set) var phase: Phase = .idle
    @Published private(set) var presentedReview: SiteRootConvergenceReview?
    private let service: SiteRootConvergenceServiceV2?
    private let authorityOrigin: URL?
    private var pending: Pending?

    private enum Pending {
        case provision(SiteRootBundleReceiptProvisionPresentationV1)
        case siteX509(SiteX509FirstProvisionPresentationV1)
        case siteX509Broker(SiteX509FirstProvisionBrokerPresentationV1)
        case siteX509ContinuationRecovery(SiteX509ContinuationRecoveryPresentationV1)
        case acknowledgement(SiteRootConvergenceAckPresentationV2)
    }

    init(
        transport: (any MonasSiteRootConvergenceSubmitting)?,
        authorityOrigin: URL? = nil
    ) {
        self.authorityOrigin = authorityOrigin ?? transport?.authorityOrigin
        service = transport.map { SiteRootConvergenceServiceV2(transport: $0) }
    }

    func accept(qrText: String) {
        guard phase == .idle, service != nil else {
            phase = .failed(.siteRootAuthorityUnavailable)
            return
        }
        do {
            let seconds = try Self.nowSeconds()
            let review: SiteRootConvergenceReview
            if qrText.contains(SiteRootConvergenceProfileV2.x509ContinuationRecoverySchema) {
                let presentation = try SiteX509ContinuationRecoveryPresentationV1(
                    qrText: qrText, nowUnixSeconds: seconds
                )
                pending = .siteX509ContinuationRecovery(presentation)
                review = SiteRootConvergenceReview(
                    site: presentation.siteUUID,
                    expiresAt: Date(timeIntervalSince1970: TimeInterval(
                        presentation.expiresAtUnixSeconds
                    )),
                    kind: .siteX509Provision(generation: presentation.generation)
                )
            } else if qrText.contains(SiteRootConvergenceProfileV2.x509BrokerProvisionSchema) {
                let presentation = try SiteX509FirstProvisionBrokerPresentationV1(
                    qrText: qrText, nowUnixSeconds: seconds
                )
                pending = .siteX509Broker(presentation)
                review = SiteRootConvergenceReview(
                    site: presentation.siteUUID,
                    expiresAt: Date(timeIntervalSince1970: TimeInterval(
                        presentation.expiresAtUnixSeconds
                    )),
                    kind: .siteX509Provision(generation: presentation.generation)
                )
            } else if qrText.contains(SiteRootConvergenceProfileV2.x509ProvisionSchema) {
                let presentation = try SiteX509FirstProvisionPresentationV1(
                    qrText: qrText, nowUnixSeconds: seconds
                )
                pending = .siteX509(presentation)
                review = SiteRootConvergenceReview(
                    site: presentation.siteUUID,
                    expiresAt: Date(timeIntervalSince1970: TimeInterval(
                        presentation.expiresAtUnixSeconds
                    )),
                    kind: .siteX509Provision(generation: presentation.generation)
                )
            } else if qrText.contains(SiteRootConvergenceProfileV2.provisionSchema) {
                let presentation = try SiteRootBundleReceiptProvisionPresentationV1(
                    qrText: qrText, nowUnixSeconds: seconds
                )
                pending = .provision(presentation)
                review = SiteRootConvergenceReview(
                    site: presentation.siteTrustDomain,
                    expiresAt: Date(timeIntervalSince1970: TimeInterval(
                        presentation.expiresAtUnixSeconds
                    )),
                    kind: .bundleReceiptProvision(
                        generation: presentation.receiptKeyGeneration
                    )
                )
            } else {
                guard let authorityOrigin else {
                    throw PlatformFailure.siteRootAuthorityUnavailable
                }
                let presentation = try SiteRootConvergenceAckPresentationV2(
                    qrText: qrText,
                    authorityOrigin: authorityOrigin,
                    nowUnixMilliseconds: seconds * 1_000
                )
                pending = .acknowledgement(presentation)
                review = SiteRootConvergenceReview(
                    site: presentation.assertion.siteUUIDText,
                    expiresAt: Date(timeIntervalSince1970: TimeInterval(
                        presentation.assertion.expiresAtUnixMilliseconds
                    ) / 1_000),
                    kind: .acknowledgement(
                        action: presentation.assertion.action,
                        rootGeneration: presentation.assertion.rootGeneration,
                        trustRevision: presentation.assertion.trustRevision
                    )
                )
            }
            presentedReview = review
            phase = .review(review)
        } catch let failure as PlatformFailure {
            phase = .failed(failure)
        } catch {
            phase = .failed(.qrPayloadUnsupported)
        }
    }

    func approve() async {
        guard case .review = phase, let pending, let service else { return }
        phase = .authenticating
        do {
            switch pending {
            case let .provision(value):
                try await service.provisionBundleReceipt(value) {
                    self.phase = .unlockingBundleReceipt
                }
            case let .siteX509(value): try await service.provisionSiteX509(value)
            case let .siteX509Broker(value): try await service.provisionSiteX509Broker(value)
            case let .siteX509ContinuationRecovery(value):
                try await service.continueRecoveredSiteX509(value)
            case let .acknowledgement(value): try await service.acknowledge(value)
            }
            self.pending = nil
            phase = .completed
        } catch let failure as PlatformFailure {
            self.pending = nil
            phase = .failed(failure)
        } catch {
            self.pending = nil
            phase = .failed(.siteRootAuthorityUnavailable)
        }
    }

    func reset() {
        pending = nil
        presentedReview = nil
        phase = .idle
    }

    private static func nowSeconds() throws -> UInt64 {
        let value = Date().timeIntervalSince1970
        guard value >= 0, value <= TimeInterval(UInt64.max) else {
            throw PlatformFailure.invalidConfiguration
        }
        return UInt64(value)
    }
}
