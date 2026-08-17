import Foundation

struct SiteX509FirstProvisionOfflineReview: Identifiable, Equatable {
    let id: Data
    let site: String
    let generations: String
    let enrolledDevice: String
    let target: String
    let services: String
    let expiry: String
}

/// Keeps the public offline response in memory for operator-controlled return.
@MainActor
final class SiteX509FirstProvisionOfflineCoordinator: ObservableObject {
    enum Phase: Equatable { case idle, review, approving, completed, failed }
    @Published private(set) var phase: Phase = .idle
    @Published private(set) var failure: PlatformFailure?
    @Published private(set) var presentedReview: SiteX509FirstProvisionOfflineReview?
    @Published private(set) var responseQRText: String?
    private let producer: SecureEnclaveSiteX509FirstProvisionOfflineProducerV2
    private var pending: SiteX509FirstProvisionOfflinePresentationV2?

    init(producer: SecureEnclaveSiteX509FirstProvisionOfflineProducerV2 = .init()) {
        self.producer = producer
    }

    func accept(qrText: String, nowUnixSeconds: UInt64 = UInt64(Date().timeIntervalSince1970)) {
        do {
            let value = try SiteX509FirstProvisionOfflinePresentationV2(
                qrText: qrText, nowUnixSeconds: nowUnixSeconds
            )
            accept(value)
        } catch let failure as PlatformFailure {
            reset(); self.failure = failure; phase = .failed
        } catch { reset(); failure = .productionEnvelopeUnavailable; phase = .failed }
    }

    func accept(fileBytes: Data, nowUnixSeconds: UInt64 = UInt64(Date().timeIntervalSince1970)) {
        do {
            guard !fileBytes.isEmpty,
                  fileBytes.count <= SiteX509FirstProvisionOfflineProfileV2.maximumPresentationFileBytes
            else { throw PlatformFailure.qrPayloadUnsupported }
            accept(try SiteX509FirstProvisionOfflinePresentationV2(
                fileBytes: fileBytes, nowUnixSeconds: nowUnixSeconds
            ))
        } catch let failure as PlatformFailure {
            reset(); self.failure = failure; phase = .failed
        } catch { reset(); failure = .productionEnvelopeUnavailable; phase = .failed }
    }

    func approve(nowUnixSeconds: UInt64 = UInt64(Date().timeIntervalSince1970)) async {
        guard let pending else { failure = .invalidConfiguration; phase = .failed; return }
        do {
            phase = .approving
            let response = try await producer.produce(pending, nowUnixSeconds: nowUnixSeconds)
            responseQRText = try SecureEnclaveSiteX509FirstProvisionOfflineProducerV2
                .responseQRText(response)
            phase = .completed
        } catch let failure as PlatformFailure {
            responseQRText = nil; self.failure = failure; phase = .failed
        } catch {
            responseQRText = nil; failure = .productionEnvelopeUnavailable; phase = .failed
        }
    }

    func reset() {
        pending = nil; presentedReview = nil; responseQRText = nil; failure = nil; phase = .idle
    }

    private func accept(_ value: SiteX509FirstProvisionOfflinePresentationV2) {
        pending = value
        presentedReview = .init(
            id: value.presentationDigest,
            site: "\(value.siteTrustDomain) · \(value.siteUUID.hex)",
            generations: "Authority \(value.authorityGeneration); custody \(value.custodyGeneration); revocation \(value.revocationGeneration); root/issuer \(value.generation)",
            enrolledDevice: "\(value.installationID) · \(value.deviceID) · \(value.appAttestApplicationID)",
            target: "\(value.targetKind) · \(value.targetID.hex)",
            services: value.services.map { "\($0.serviceID): \($0.privateIPs.joined(separator: ", "))" }.joined(separator: "\n"),
            expiry: Date(timeIntervalSince1970: TimeInterval(value.expiresAt)).formatted()
        )
        phase = .review
    }
}

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
