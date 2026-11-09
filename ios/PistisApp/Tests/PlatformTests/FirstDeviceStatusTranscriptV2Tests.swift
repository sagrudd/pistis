import Foundation
import XCTest
@testable import Pistis

final class FirstDeviceStatusTranscriptV2Tests: XCTestCase {
    func testSharedStatusVector() throws {
        let value = FirstDeviceStatusTranscriptV2(
            nonce: Data(96...127), operationID: Data(1...16),
            correlationDigest: Data([0xf8,0x46,0xc9,0x78,0xde,0xdf,0x75,0xc3,0x07,0x9b,0x33,0x6f,0x7b,0xae,0xc0,0xce,0x62,0xed,0xb2,0x94,0x00,0x27,0xcc,0x25,0x1c,0xd0,0x63,0x28,0x50,0xee,0x23,0xcd]),
            reference: "genesis-reference-1", installationID: Data(160...175),
            site: "site-6073349b-e7f6-420f-ba7c-586b6d9ad78e", presentationDigest: Data(176...207),
            receiptDigest: Data(208...239), tlsSPKIDigest: Data(repeating: 0x10, count: 32),
            appAttestKeyID: Data(repeating: 0x11, count: 32), siteRootKeyDigest: Data(repeating: 0x12, count: 32),
            deviceKeyDigest: Data(repeating: 0x13, count: 32), expiry: 1_900_000_060)
        XCTAssertEqual(try value.clientDataHash().map { String(format: "%02x", $0) }.joined(),
                       "e00ad831caab2341c8d2ced32915570555bc3359dc26f60318527c588bef330b")
    }
}
