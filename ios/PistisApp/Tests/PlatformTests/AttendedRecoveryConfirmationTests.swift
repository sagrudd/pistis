import Foundation
import XCTest
@testable import Pistis

final class AttendedRecoveryConfirmationTests: XCTestCase {
    func testRequiresExactMatchAndConsumesOnce() throws {
        let code = Data(1...8)
        var value = try AttendedRecoveryConfirmation(comparison: code, expiry: 10, now: 1)
        XCTAssertThrowsError(try value.consume(now: 2))
        var valid = try AttendedRecoveryConfirmation(comparison: code, expiry: 10, now: 1)
        try valid.confirm(displayed: code, now: 2)
        try valid.consume(now: 3)
        XCTAssertThrowsError(try valid.consume(now: 4))
    }

    func testMismatchCancellationAndExpiryDeny() throws {
        let code = Data(1...8)
        var mismatch = try AttendedRecoveryConfirmation(comparison: code, expiry: 10, now: 1)
        XCTAssertThrowsError(try mismatch.confirm(displayed: Data(repeating: 1, count: 8), now: 2))
        XCTAssertThrowsError(try mismatch.confirm(displayed: code, now: 3))
        var cancelled = try AttendedRecoveryConfirmation(comparison: code, expiry: 10, now: 1)
        try cancelled.confirm(displayed: code, now: 2); cancelled.cancel()
        XCTAssertThrowsError(try cancelled.consume(now: 3))
        var expired = try AttendedRecoveryConfirmation(comparison: code, expiry: 10, now: 1)
        try expired.confirm(displayed: code, now: 2)
        XCTAssertThrowsError(try expired.consume(now: 10))
        XCTAssertThrowsError(try AttendedRecoveryConfirmation(comparison: code, expiry: 10, now: 10))
    }
}
