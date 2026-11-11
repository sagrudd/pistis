import Foundation

/// In-memory interaction state only; it is not an authority or durable replay fence.
@MainActor
final class AttendedRecoveryConfirmation {
    private enum State { case awaiting, confirmed, cancelled, consumed }
    private var state: State = .awaiting
    private let expected: Data
    private let expiry: UInt64

    init(comparison: Data, expiry: UInt64, now: UInt64) throws {
        guard comparison.count == 8, expiry > now else { throw PlatformFailure.invalidConfiguration }
        expected = comparison
        self.expiry = expiry
    }

    func confirm(displayed: Data, now: UInt64) throws {
        guard case .awaiting = state else { throw PlatformFailure.invalidConfiguration }
        guard now < expiry, displayed == expected else {
            state = .cancelled
            throw PlatformFailure.invalidConfiguration
        }
        state = .confirmed
    }

    func cancel() { state = .cancelled }

    func consume(now: UInt64) throws {
        guard case .confirmed = state, now < expiry else {
            state = .cancelled
            throw PlatformFailure.invalidConfiguration
        }
        state = .consumed
    }
}
