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
    func testDisplayAddressesAreBoundToTheSignedDigest() throws {
        let wrapper = Data(base64Encoded: "UFhSVy92MQEBAm1QWFJOL3YxAQEAEAEBAQEBAQEBAQEBAQEBAQECAARzaXRlAwARc2VydmljZS1tb25hcy13ZWIEACDlD7BlWtKwL/pLsjlsx+ysr2lG44TXNH5FkXiYMx2XSgUACAAAAAAAAAABBgAQAwMDAwMDAwMDAwMDAwMDAwcAEAQEBAQEBAQEBAQEBAQEBAQIAAgAAAAAAAAAAQkACAAAAAAAAAABCgAIAAAAAAAAAAELAARyb290DAAGaXNzdWVyDQAgBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUOACAGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBg8AIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHEAAgCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgRAAgAAAAAAAAAZBIAIAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJEwAgBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcUABAKCgoKCgoKCgoKCgoKCgoKFQAQAAAAAAAAAGQAAAAAAAAAyBYAIAsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLFwBADAwMDAwMDAwMDAwMDAwMDA0NDQ0NDQ0NDQ0NDQ0NDQ0ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODhgAMA8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PAAAAAAAAAGQAAAAAAAABkBkACAAAAAAAAAABGgAIAAAAAAAAAAECAAUEwKgBwA==")!
        XCTAssertEqual(SHA256.hash(data: wrapper).map { String(format: "%02x", $0) }.joined(),
                       "e6c78c3a77c9044703acd12c4da1ffbf47c03a956e875628ad6c8b2d929609ca")
        let presentation = try FixedMonasLeafRenewalPresentationV1(wrapper, now: 150) {
            Data(SHA256.hash(data: $0))
        }
        XCTAssertEqual(presentation.addresses, [Data([192, 168, 1, 192])])
        var changed = wrapper
        changed[changed.count - 1] ^= 1
        XCTAssertThrowsError(try FixedMonasLeafRenewalPresentationV1(changed, now: 150) {
            Data(SHA256.hash(data: $0))
        })
    }

}
