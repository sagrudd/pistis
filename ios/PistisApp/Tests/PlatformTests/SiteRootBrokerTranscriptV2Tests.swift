import Foundation
import XCTest
@testable import Pistis

final class SiteRootBrokerTranscriptV2Tests: XCTestCase {
    private let operation = Data(1...16)
    private let correlation = Data(32...63)
    private let challenge = Data(64...95)
    private let reference = "genesis-reference-1"

    func testCrossImplementationTranscriptVector() throws {
        let hash = try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
            operationID: operation, correlation: correlation, reference: reference, hostChallenge: challenge
        )
        XCTAssertEqual(hash.map { String(format: "%02x", $0) }.joined(),
                       "deacc0e56043da308a1b92a8da19555b6892e06d5add06e321d6c198e1e33d62")
    }

    func testSwappedInputsAndMalformedValuesAreRejectedOrChangeHash() throws {
        let hash = try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
            operationID: operation, correlation: correlation, reference: reference, hostChallenge: challenge
        )
        for changed in [
            try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
                operationID: Data(repeating: 9, count: 16), correlation: correlation,
                reference: reference, hostChallenge: challenge),
            try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
                operationID: operation, correlation: Data(repeating: 9, count: 32),
                reference: reference, hostChallenge: challenge),
            try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
                operationID: operation, correlation: correlation,
                reference: "other", hostChallenge: challenge),
            try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
                operationID: operation, correlation: correlation,
                reference: reference, hostChallenge: Data(repeating: 9, count: 32)),
        ] { XCTAssertNotEqual(changed, hash) }
        XCTAssertThrowsError(try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
            operationID: Data(repeating: 0, count: 16), correlation: correlation,
            reference: reference, hostChallenge: challenge))
        XCTAssertThrowsError(try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
            operationID: operation, correlation: Data(repeating: 0, count: 32),
            reference: reference, hostChallenge: challenge))
        XCTAssertThrowsError(try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
            operationID: operation, correlation: correlation,
            reference: "invalid/reference", hostChallenge: challenge))
        XCTAssertThrowsError(try SiteRootBrokerRegistrationTranscriptV2.clientDataHash(
            operationID: operation, correlation: correlation,
            reference: reference, hostChallenge: Data(repeating: 0, count: 32)))
    }
}
