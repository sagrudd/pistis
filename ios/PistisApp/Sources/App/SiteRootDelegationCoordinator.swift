import Foundation

/// UI state for the distinct, attended iPhone Site Root ceremony.
///
/// This coordinator is intentionally separate from `ProductionCeremonyCoordinator`:
/// v2 Pistis authentication must not acquire Site Root semantics by accident.
@MainActor
final class SiteRootDelegationCoordinator: ObservableObject {
    enum Phase: Equatable {
        case idle
        case review(SiteRootDelegationReview)
        case signing
        case submitted(MonasSiteRootDelegationSubmissionReceiptV1)
        case failed(PlatformFailure)
    }

    @Published private(set) var phase: Phase = .idle
    private let transport: any MonasSiteRootDelegationSubmitting
    private var qrPresentation: SiteRootDelegationQRPresentationV1?

    init(transport: any MonasSiteRootDelegationSubmitting = UnavailableMonasSiteRootDelegationTransport()) {
        self.transport = transport
    }

    func accept(qrText: String) {
        do {
            let scanned = try SiteRootDelegationQRPresentationV1(qrText: qrText)
            qrPresentation = scanned
            phase = .review(SiteRootDelegationReview(presentation: scanned.presentation))
        } catch let failure as PlatformFailure {
            phase = .failed(failure)
        } catch {
            phase = .failed(.qrPayloadUnsupported)
        }
    }

    func approve() async {
        guard let qrPresentation else {
            phase = .failed(.invalidConfiguration)
            return
        }
        phase = .signing
        do {
            let producer = try SecureEnclaveSiteRootProofProducer(
                authenticationReason: "Sign this exact Monas Site Root delegation"
            )
            let submission = try producer.prove(qrPresentation.presentation)
            let receipt = try await transport.submit(
                MonasSiteRootDelegationSubmissionRequestV1(
                    endpoint: qrPresentation.presentation.submitURL,
                    submission: submission
                )
            )
            guard receipt.reference == qrPresentation.presentation.reference else {
                throw PlatformFailure.productionEnvelopeUnavailable
            }
            phase = .submitted(receipt)
        } catch let failure as PlatformFailure {
            phase = .failed(failure)
        } catch {
            phase = .failed(.productionEnvelopeUnavailable)
        }
    }

    func reset() {
        qrPresentation = nil
        phase = .idle
    }
}

/// Redacted, non-secret facts permitted in the iPhone confirmation screen.
struct SiteRootDelegationReview: Equatable, Identifiable {
    var id: String { reference + deviceKeyFingerprint + destination }
    let reference: String
    let deviceKeyFingerprint: String
    let destination: String

    init(presentation: SiteRootDelegationPresentationV1) {
        reference = Self.redact(presentation.reference)
        deviceKeyFingerprint = Self.redact(presentation.deviceKeyID)
        destination = presentation.submitURL.host ?? "unavailable"
    }

    private static func redact(_ value: String) -> String {
        guard value.count > 12 else { return "redacted" }
        return "\(value.prefix(6))…\(value.suffix(4))"
    }
}
