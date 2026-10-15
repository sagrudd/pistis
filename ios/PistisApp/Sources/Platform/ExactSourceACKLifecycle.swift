import Foundation
import PistisCore
#if canImport(LocalAuthentication) && canImport(Security) && canImport(UIKit)
import UIKit

/// Cancellation/current-wall signal only, never biometric or signing authority.
/// It exists before the first preparation await and outlives the displayed task.
final class ExactSourceACKLifecycle: @unchecked Sendable {
    private let lock = NSLock()
    private let center: NotificationCenter
    private var observer: NSObjectProtocol?
    private var stopped = false
    private var wallFloor: Date
    private var invocation: IssuerCeremonyLifecycle?

    init(center: NotificationCenter = .default, initialWall: Date = Date()) {
        self.center = center
        wallFloor = initialWall
        observer = center.addObserver(forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: nil) { [weak self] _ in self?.invalidate() }
    }
    deinit { if let observer { center.removeObserver(observer) } }
    func invalidate() {
        lock.lock(); stopped = true; let current = invocation; lock.unlock()
        current?.invalidate()
    }
    func bind(_ current: IssuerCeremonyLifecycle) throws {
        lock.lock(); let denied = stopped
        if !denied { invocation = current }
        lock.unlock()
        if denied { current.invalidate(); throw IssuerPhoneError.uncertain }
    }
    /// Updates only the observed floor. A rollback above the initial start is
    /// still terminal, and restoring a later wall value cannot resurrect it.
    @discardableResult
    func observe(wall: Date = Date()) throws -> Date {
        lock.lock()
        let denied = stopped || wall < wallFloor
        if denied { stopped = true } else { wallFloor = wall }
        let current = invocation
        lock.unlock()
        if denied { current?.invalidate(); throw IssuerPhoneError.uncertain }
        return wall
    }
    @discardableResult
    func validate(issuedAt: UInt64, expiresAt: UInt64, actionIssuedAt: UInt64,
                  actionExpiresAt: UInt64, taskExpiresAt: UInt64, wall: Date = Date()) throws -> Date {
        let observed = try observe(wall: wall)
        let seconds = observed.timeIntervalSince1970
        guard seconds >= Double(issuedAt), seconds >= Double(actionIssuedAt),
              seconds < Double(expiresAt), seconds < Double(actionExpiresAt),
              seconds < Double(taskExpiresAt) else {
            invalidate(); throw IssuerPhoneError.expired
        }
        return observed
    }

}
#endif
