import Foundation
import PistisCore
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)
import UIKit

/// One deliberate action, holding comparison originals and one original bound.
/// Only authenticateCurrent creates the real private phone session; neither
/// this pending file nor the receipt creates a Mac/current-purpose owner.
@MainActor
final class IssuerMacSessionApproval {
    let pending: IssuerMacSessionWire.Pending
    let installationName: String
    private let enrollment: AuthenticatedEnrollmentOutput
    private let ack: SiteRootConvergenceAckRecordV2
    private let lifecycle: ExactSourceACKLifecycle
    private let end: ContinuousClock.Instant
    private var consumed = false
    private var session: IssuerNativeCurrentSession?

    private init(pending: IssuerMacSessionWire.Pending, enrollment: AuthenticatedEnrollmentOutput,
                 ack: SiteRootConvergenceAckRecordV2, lifecycle: ExactSourceACKLifecycle,
                 end: ContinuousClock.Instant) {
        self.pending = pending; self.enrollment = enrollment; self.ack = ack
        self.lifecycle = lifecycle; self.end = end
        installationName = enrollment.trust.displayName
    }
    static func prepare(fileBytes: Data, expectedInstallation: UUID? = nil) async throws -> IssuerMacSessionApproval {
        let lifecycle = ExactSourceACKLifecycle()
        let sampled = ContinuousClock().now
        do {
            try Task.checkCancellation()
            let now = try lifecycle.observe()
            guard UIApplication.shared.applicationState == .active,
                  let enrollment = try await InstallationTrustKeychain.shared.activeEnrollment() else { throw IssuerPhoneError.unavailable }
            if let expectedInstallation {
                guard try IssuerNativeSessionWire.uuid(enrollment.trust.installationID) == expectedInstallation else { throw IssuerPhoneError.binding }
            }
            let ack = try SiteRootConvergenceAckStoreV2().current()
            let pending = try IssuerMacSessionWire.Pending(fileBytes, now: now)
            try pending.check(enrollment: enrollment, ack: ack, now: lifecycle.observe())
            let left = min(30, min(Double(pending.expiresAt), enrollment.trust.expiresAt.timeIntervalSince1970) - now.timeIntervalSince1970)
            guard left.isFinite, left > 0 else { throw IssuerPhoneError.expired }
            // Anchor precedes the wall sample and ALL preparation awaits. No
            // import, review, Face ID, receipt or retry renews this attempt.
            let end = sampled.advanced(by: .nanoseconds(Int64((left * 1_000_000_000).rounded(.down))))
            let owner = IssuerMacSessionApproval(pending: pending, enrollment: enrollment,
                ack: ack, lifecycle: lifecycle, end: end)
            try await owner.check()
            return owner
        } catch { lifecycle.invalidate(); throw error }
    }
    func cancel() {
        consumed = true; lifecycle.invalidate(); session?.invalidate(); session = nil
    }
    private func check() async throws {
        try Task.checkCancellation()
        let now = try lifecycle.observe()
        guard UIApplication.shared.applicationState == .active, ContinuousClock().now < end,
              try await InstallationTrustKeychain.shared.activeEnrollment() == enrollment,
              try SiteRootConvergenceAckStoreV2().current() == ack else { throw IssuerPhoneError.binding }
        try pending.check(enrollment: enrollment, ack: ack, now: now)
        try Task.checkCancellation()
        try lifecycle.observe()
        guard ContinuousClock().now < end else { throw IssuerPhoneError.expired }
    }
    func approve() async throws {
        guard !consumed else { throw IssuerPhoneError.order }
        consumed = true
        let lifecycle = self.lifecycle
        try await withTaskCancellationHandler {
            do {
                try await check()
                let current = try await IssuerNativeCurrentSession.authenticateCurrent(before: end)
                session = current
                defer { current.invalidate(); session = nil }
                guard current.enrollment == enrollment else { throw IssuerPhoneError.binding }
                try await check()
                let request = try pending.request()
                let receipt = try await IssuerSiteRootTransport.bindMacSession(request, current: current, deadline: end)
                try await check()
                try IssuerMacSessionWire.receipt(receipt, pending: pending, now: lifecycle.observe())
                try await check()
                lifecycle.invalidate()
            } catch { cancel(); throw error }
        } onCancel: { lifecycle.invalidate() }
    }
}
#endif
