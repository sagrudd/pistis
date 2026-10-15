import Foundation
import PistisCore

/// Scheduling/lookup guard only. This accepts no owner or key capability and
/// is not a signing factory. The concrete signer supplies the real fixed clock,
/// cancellation signal, existing Keychain lookup and SecKey invocation.
enum IssuerSignatureInvocationBoundary {
    static func perform<Key, Output>(
        originalDeadline: ContinuousClock.Instant,
        now: () -> ContinuousClock.Instant = { ContinuousClock().now },
        checkCancellation: () throws -> Void,
        lookup: () throws -> Key,
        invoke: (Key) throws -> Output
    ) throws -> Output {
        func check() throws {
            try checkCancellation()
            guard now() < originalDeadline else { throw IssuerPhoneError.expired }
        }
        try check()
        let existingKey = try lookup()
        // Last operation before invoking the signature closure. A delayed or
        // cancelled lookup cannot reach the concrete SecKeyCreateSignature.
        try check()
        let result = try invoke(existingKey)
        // Completion after expiry is uncertain, never retained as a new result.
        try check()
        return result
    }
}

#if canImport(LocalAuthentication) && canImport(Security)

/// A synchronous cancellation signal, not stored biometric authority. Background
/// or task cancellation invalidates the exact live context immediately.
final class IssuerCeremonyLifecycle: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private let ceremony: FaceIDCeremonyContext
    init(ceremony: FaceIDCeremonyContext) { self.ceremony = ceremony }
    func invalidate() {
        lock.lock(); cancelled = true; lock.unlock()
        ceremony.invalidate()
    }
    func check() throws {
        lock.lock(); let stopped = self.cancelled; lock.unlock()
        guard !stopped else { throw IssuerPhoneError.uncertain }
    }
}
#endif
