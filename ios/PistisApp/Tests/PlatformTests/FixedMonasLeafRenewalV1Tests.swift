import Foundation
import CryptoKit
import XCTest

@testable import Pistis

final class FixedMonasLeafRenewalV1Tests: XCTestCase {
    private let fixture = Data(base64Encoded: "UFhSTi92MQEBABABAQEBAQEBAQEBAQEBAQEBAgAEc2l0ZQMAEXNlcnZpY2UtbW9uYXMtd2ViBAAgAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIFAAgAAAAAAAAAAQYAEAMDAwMDAwMDAwMDAwMDAwMHABAEBAQEBAQEBAQEBAQEBAQECAAIAAAAAAAAAAEJAAgAAAAAAAAAAQoACAAAAAAAAAABCwAEcm9vdAwABmlzc3Vlcg0AIAUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFDgAgBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYPACAHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBxAAIAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEQAIAAAAAAAAAGQSACAJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCRMAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHFAAQCgoKCgoKCgoKCgoKCgoKChUAEAAAAAAAAABkAAAAAAAAAMgWACALCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCxcAQAwMDAwMDAwMDAwMDAwMDAwNDQ0NDQ0NDQ0NDQ0NDQ0NDg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4YADAPDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDwAAAAAAAABkAAAAAAAAAZAZAAgAAAAAAAAAARoACAAAAAAAAAAB")!

    func testJointTranscriptMatchesRustFixture() throws {
        let point = Data(base64Encoded: "A2sX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW")!
        var transcript = Data("PXRN/v2\u{1}".utf8)
        for (index, field) in [fixture, Data(repeating: 1, count: 16), point, point, point].enumerated() {
            transcript.append(UInt8(index + 1))
            transcript.append(UInt8(field.count >> 8)); transcript.append(UInt8(field.count & 255))
            transcript.append(field)
        }
        XCTAssertEqual(SHA256.hash(data: transcript).map { String(format: "%02x", $0) }.joined(),
                       "eecac34c0f507a716d1c7b296eb985605825440beaa10553bcdca9cf3ce1f7ca")
        let parsed = try FixedMonasLeafRenewalV2(transcript, now: 150)
        XCTAssertEqual(parsed.devicePoint, point)
        XCTAssertNotEqual(parsed.rolePayload(.device), parsed.rolePayload(.root))
        var trailing = transcript; trailing.append(0)
        XCTAssertThrowsError(try FixedMonasLeafRenewalV2(trailing, now: 150))
    }

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
        let otherSite = SiteRootConvergenceAckRecordV2(
            siteUUID: "02020202-0202-0202-0202-020202020202",
            targetIDB64URL: "public", ackPublicKeyB64URL: "public", generation: 1
        )
        XCTAssertThrowsError(try statement.validateCurrentSigner(otherSite))
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
        let presentation = try FixedMonasLeafRenewalPresentationV1(wrapper, now: 150)
        XCTAssertEqual(presentation.addresses, [Data([192, 168, 1, 192])])
        let point = Data(base64Encoded: "A2sX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW")!
        var joint = Data("PXRN/v2\u{1}".utf8)
        func add(_ tag: UInt8, _ value: Data, to result: inout Data) {
            result.append(tag); result.append(UInt8(value.count >> 8)); result.append(UInt8(value.count & 255)); result.append(value)
        }
        for (index, value) in [presentation.statement.exactBytes, Data(repeating: 1, count: 16), point, point, point].enumerated() {
            add(UInt8(index + 1), value, to: &joint)
        }
        let priorLength = Int(wrapper[9]) * 256 + Int(wrapper[10])
        let addressField = wrapper.subdata(in: (11 + priorLength)..<wrapper.count)
        var jointWrapper = Data("PXRW/v2\u{1}".utf8)
        add(1, joint, to: &jointWrapper); jointWrapper.append(addressField)
        XCTAssertEqual(try FixedMonasLeafRenewalPresentationV2(jointWrapper, now: 150).addresses,
                       presentation.addresses)
        var invalidJoint = jointWrapper; invalidJoint[invalidJoint.count - 1] ^= 1
        XCTAssertThrowsError(try FixedMonasLeafRenewalPresentationV2(invalidJoint, now: 150))
        XCTAssertTrue(FixedMonasLeafRenewalProducerV1.matchesIndependentDigest(
            "e6c78c3a77c9044703acd12c4da1ffbf47c03a956e875628ad6c8b2d929609ca",
            presentation: presentation
        ))
        XCTAssertFalse(FixedMonasLeafRenewalProducerV1.matchesIndependentDigest(
            "different", presentation: presentation
        ))
        var changed = wrapper
        changed[changed.count - 1] ^= 1
        XCTAssertThrowsError(try FixedMonasLeafRenewalPresentationV1(changed, now: 150))
    }

}
