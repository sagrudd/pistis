import Foundation
import PistisCore
import XCTest
@testable import Pistis

final class IssuerSignatureInvocationBoundaryTests: XCTestCase {
    func testDelayedExistingKeyLookupCrossingOriginalDeadlineNeverInvokes() throws {
        let start = ContinuousClock().now
        let deadline = start.advanced(by: .seconds(2))
        var now = start
        var invocations = 0
        XCTAssertThrowsError(try IssuerSignatureInvocationBoundary.perform(
            originalDeadline: deadline, now: { now }, checkCancellation: {},
            lookup: { now = deadline; return "test lookup result, not a SecKey" },
            invoke: { _ in invocations += 1; return Data([1]) }
        )) { XCTAssertEqual($0 as? IssuerPhoneError, .expired) }
        XCTAssertEqual(invocations, 0)
    }
    func testCancellationDuringLookupNeverInvokesAndPostInvocationExpiryDenies() throws {
        let start = ContinuousClock().now
        let deadline = start.advanced(by: .seconds(2))
        var now = start, cancelled = false
        var invocations = 0
        XCTAssertThrowsError(try IssuerSignatureInvocationBoundary.perform(
            originalDeadline: deadline, now: { now },
            checkCancellation: { if cancelled { throw IssuerPhoneError.uncertain } },
            lookup: { cancelled = true; return 1 },
            invoke: { _ in invocations += 1; return Data([1]) }
        ))
        XCTAssertEqual(invocations, 0)
        cancelled = false
        XCTAssertThrowsError(try IssuerSignatureInvocationBoundary.perform(
            originalDeadline: deadline, now: { now }, checkCancellation: {},
            lookup: { 1 },
            invoke: { _ in invocations += 1; now = deadline; return Data([1]) }
        )) { XCTAssertEqual($0 as? IssuerPhoneError, .expired) }
        XCTAssertEqual(invocations, 1, "overdue invocation must not return a retained success")
    }
    func testReplacedLookupKeyCannotReachInvocationAndValidationCannotExtendEnd() throws {
        let start = ContinuousClock().now
        let deadline = start.advanced(by: .seconds(2))
        let selected = Data([1]), replacement = Data([2])
        var invocations = 0
        XCTAssertThrowsError(try IssuerSignatureInvocationBoundary.perform(
            originalDeadline: deadline, now: { start }, checkCancellation: {},
            lookup: { replacement },
            validate: { actual in guard actual == selected else { throw IssuerPhoneError.binding } },
            invoke: { _ in invocations += 1; return Data([3]) }
        )) { XCTAssertEqual($0 as? IssuerPhoneError, .binding) }
        XCTAssertEqual(invocations, 0)
        var now = start
        XCTAssertThrowsError(try IssuerSignatureInvocationBoundary.perform(
            originalDeadline: deadline, now: { now }, checkCancellation: {},
            lookup: { selected }, validate: { _ in now = deadline },
            invoke: { _ in invocations += 1; return Data([3]) }
        )) { XCTAssertEqual($0 as? IssuerPhoneError, .expired) }
        XCTAssertEqual(invocations, 0)
    }

}
