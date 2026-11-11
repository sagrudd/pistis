import XCTest
@testable import Pistis

final class AttendedRecoveryComparisonTests: XCTestCase {
    func testDisplaysAllEightBytesInFourGroups() throws {
        XCTAssertEqual(try AttendedRecoveryComparison.format(Data([0x18, 0x68, 0x66, 0xe4, 0xac, 0xb0, 0xe2, 0xd4])), "1868-66E4-ACB0-E2D4")
        XCTAssertEqual(try AttendedRecoveryComparison.format(Data(repeating: 0, count: 8)), "0000-0000-0000-0000")
    }

    func testExpiryIsUnambiguousUTC() {
        XCTAssertEqual(AttendedRecoveryComparison.expiry(Date(timeIntervalSince1970: 0)), "1970-01-01T00:00:00Z")
    }

    func testRejectsPartialOrExtraBytes() {
        XCTAssertThrowsError(try AttendedRecoveryComparison.format(Data(repeating: 1, count: 7)))
        XCTAssertThrowsError(try AttendedRecoveryComparison.format(Data(repeating: 1, count: 9)))
    }
}
