import CryptoKit
import Darwin
import Foundation

struct FixedMonasLeafRenewalReviewV1: Identifiable {
    let id: Data
    let site: String
    let addresses: String
    let digest: String
    let predecessor: String
    let successorExpiry: String
    let expiry: String
}

/// Offline public presentation only. The returned proof does not establish
/// issuer, trust, activation, or service readiness.
@MainActor
final class FixedMonasLeafRenewalCoordinatorV1: ObservableObject {
    enum Phase { case idle, review, approving, completed, failed }
    @Published private(set) var phase: Phase = .idle
    @Published private(set) var presentedReview: FixedMonasLeafRenewalReviewV1?
    @Published private(set) var responseQRText: String?
    private var pending: FixedMonasLeafRenewalPresentationV1?

    func accept(qrText: String) {
        reset()
        guard qrText.hasPrefix("PXRN1:P:") else { phase = .failed; return }
        let raw = String(qrText.dropFirst("PXRN1:P:".count))
        guard !raw.isEmpty, raw.utf8.count <= 4096,
              raw.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) ||
                  (97...122).contains($0) || $0 == 45 || $0 == 95 }) else {
            phase = .failed; return
        }
        let encoded = raw.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let padded = encoded + String(repeating: "=", count: (4 - encoded.count % 4) % 4)
        guard let data = Data(base64Encoded: padded),
              Self.base64url(data) == raw else { phase = .failed; return }
        accept(fileBytes: data)
    }

    func accept(fileBytes data: Data) {
        reset()
        guard !data.isEmpty, data.count <= 4096 else { phase = .failed; return }
        do {
            let clock = Date().timeIntervalSince1970
            guard clock >= 0 else { throw FixedMonasLeafRenewalV1.Invalid.denied }
            let now = UInt64(clock)
            let value = try FixedMonasLeafRenewalPresentationV1(data, now: now)
            let addresses = try value.addresses.map(Self.addressText).joined(separator: ", ")
            let digest = Data(SHA256.hash(data: data))
            pending = value
            presentedReview = FixedMonasLeafRenewalReviewV1(
                id: digest,
                site: value.statement.siteUUID.map { String(format: "%02x", $0) }.joined(),
                addresses: addresses,
                digest: digest.map { String(format: "%02x", $0) }.joined(),
                predecessor: value.statement.predecessorLeafDigest.map { String(format: "%02x", $0) }.joined()
                    + " · expired " + Date(timeIntervalSince1970: TimeInterval(value.statement.predecessorNotAfter)).formatted(),
                successorExpiry: Date(timeIntervalSince1970: TimeInterval(value.statement.successorNotAfter)).formatted(),
                expiry: Date(timeIntervalSince1970: TimeInterval(value.statement.expiresAt)).formatted()
            )
            phase = .review
        } catch { phase = .failed }
    }

    func approve(independentDigest: String) async {
        guard let pending else { phase = .failed; return }
        phase = .approving
        do {
            let proof = try await FixedMonasLeafRenewalProducerV1()
                .produce(pending, independentlyReadDigest: independentDigest)
            responseQRText = "PXRN1:R:" + Self.base64url(proof)
            phase = .completed
        } catch { responseQRText = nil; phase = .failed }
    }

    func reset() {
        pending = nil; presentedReview = nil; responseQRText = nil; phase = .idle
    }

    private static func base64url(_ bytes: Data) -> String {
        bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private static func addressText(_ bytes: Data) throws -> String {
        let family = bytes.count == 4 ? AF_INET : AF_INET6
        guard bytes.count == 4 || bytes.count == 16 else { throw FixedMonasLeafRenewalV1.Invalid.denied }
        var result = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let success = bytes.withUnsafeBytes { raw in
            inet_ntop(family, raw.baseAddress, &result, socklen_t(result.count))
        }
        guard success != nil else { throw FixedMonasLeafRenewalV1.Invalid.denied }
        return String(cString: result)
    }
}
