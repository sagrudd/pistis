import Foundation
import XCTest
@testable import Pistis
final class ExactSourceACKHeadersTests: XCTestCase {
    func testACKGenerationHeadersContainOnlyAlgAndEightByteKid() throws {
        XCTAssertEqual(try DetachedES256Cose.protectedHeaders(ackGeneration: 1), Data([0xa2,0x01,0x26,0x04,0x48,0,0,0,0,0,0,0,1]))
        XCTAssertEqual(try DetachedES256Cose.protectedHeaders(ackGeneration: 0x0102030405060708), Data([0xa2,0x01,0x26,0x04,0x48,1,2,3,4,5,6,7,8]))
        XCTAssertThrowsError(try DetachedES256Cose.protectedHeaders(ackGeneration: 0))
        XCTAssertNotEqual(try DetachedES256Cose.protectedHeaders(ackGeneration: 1), try DetachedES256Cose.protectedHeaders(kid:"1"))
    }
}
