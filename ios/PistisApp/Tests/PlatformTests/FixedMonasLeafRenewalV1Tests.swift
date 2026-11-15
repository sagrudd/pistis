import Foundation
import CryptoKit
import XCTest

@testable import Pistis

final class FixedMonasLeafRenewalV1Tests: XCTestCase {
    private let fixture = Data(base64Encoded: "UFhSTi92MQEBABABAQEBAQEBAQEBAQEBAQEBAgAEc2l0ZQMAEXNlcnZpY2UtbW9uYXMtd2ViBAAgAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAAgAAAAAAAAAAQYAEAMDAwMDAwMDAwMDAwMDAwMHABAEBAQEBAQEBAQEBAQEBAQECAAIAAAAAAAAAAEJAAgAAAAAAAAAAQoACAAAAAAAAAABCwAEcm9vdAwABmlzc3Vlcg0AIAUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFDgAgBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYPACAHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBxAAIAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEQAIAAAAAAAAAGQSACAJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCRMAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHFAAQCgoKCgoKCgoKCgoKCgoKChUAEAAAAAAAAABkAAAAAAAAAMgWACALCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCxcAQAwMDAwMDAwMDAwMDAwMDAwNDQ0NDQ0NDQ0NDQ0NDQ0NDg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4YADAPDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDwAAAAAAAABkAAAAAAAAAZAZAAgAAAAAAAAAARoACAAAAAAAAAAB")!

    func testGoldenAndCurrentAcknowledgement() throws {
        XCTAssertEqual(fixture.count, 621)
        XCTAssertEqual(SHA256.hash(data: fixture).map { String(format: "%02x", $0) }.joined(),
                       "b540c84754538e86fa661f0e1ecd1482f5c536ef16da7981bbcc719cc5e7370a")
        let statement = try FixedMonasLeafRenewalV1(fixture, now: 150)
        XCTAssertEqual(statement.acknowledgementGeneration, 1)
        let current = SiteRootConvergenceAckRecordV2(
            siteUUID: "01010101-0101-0101-0101-010101010101",
            targetIDB64URL: "public", ackPublicKeyB64URL: "public", generation: 1
        )
        XCTAssertNoThrow(try statement.validateCurrentSigner(current))
        let stale = SiteRootConvergenceAckRecordV2(
            siteUUID: current.siteUUID, targetIDB64URL: "public",
            ackPublicKeyB64URL: "public", generation: 2
        )
        XCTAssertThrowsError(try statement.validateCurrentSigner(stale))
    }

    func testWrongTagExpiredAndTrailingAreDenied() {
        var wrongTag = fixture
        wrongTag[8] = 2
        XCTAssertThrowsError(try FixedMonasLeafRenewalV1(wrongTag, now: 150))
        XCTAssertThrowsError(try FixedMonasLeafRenewalV1(fixture, now: 400))
        var trailing = fixture
        trailing.append(0)
        XCTAssertThrowsError(try FixedMonasLeafRenewalV1(trailing, now: 150))
    }
}
