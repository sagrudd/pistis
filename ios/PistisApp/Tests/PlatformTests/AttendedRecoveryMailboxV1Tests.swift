import Foundation
import XCTest
@testable import Pistis

final class AttendedRecoveryMailboxV1Tests: XCTestCase {
    func testClosedFixedRequestAndReceipt() throws {
        let request = try AttendedRecoveryMailboxV1.request(requestID: Data(repeating: 1, count: 16),
            relaySecret: Data(repeating: 2, count: 32), intentDigest: Data(repeating: 3, count: 32), proof: Data([4]))
        XCTAssertEqual(request.url, AttendedRecoveryMailboxV1.endpoint)
        XCTAssertNil(request.url?.query)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: String])
        XCTAssertEqual(Set(object.keys), ["schema", "request_id_b64url", "phone_relay_secret_b64url", "intent_sha256_b64url", "proof_b64url"])
        let headers = ["Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store"]
        let response = try XCTUnwrap(HTTPURLResponse(url: AttendedRecoveryMailboxV1.endpoint, statusCode: 200, httpVersion: nil, headerFields: headers))
        let data = Data(#"{"schema":"mnemosyne.monas.first-install-broker.response.v1","state":"accepted"}"#.utf8)
        XCTAssertNoThrow(try AttendedRecoveryMailboxV1.validateReceipt(data, response: response))
        XCTAssertThrowsError(try AttendedRecoveryMailboxV1.validateReceipt(data + Data(" ".utf8) + data, response: response))
        let wrong = try XCTUnwrap(HTTPURLResponse(url: URL(string: "https://example.com")!, statusCode: 200, httpVersion: nil, headerFields: headers))
        XCTAssertThrowsError(try AttendedRecoveryMailboxV1.validateReceipt(data, response: wrong))
    }
    func testRejectsOversizedProofAndInvalidCapability() {
        XCTAssertThrowsError(try AttendedRecoveryMailboxV1.request(requestID: Data(repeating: 1, count: 16), relaySecret: Data(repeating: 2, count: 32), intentDigest: Data(repeating: 3, count: 32), proof: Data(repeating: 1, count: 8_193)))
        XCTAssertThrowsError(try AttendedRecoveryMailboxV1.request(requestID: Data(repeating: 1, count: 16), relaySecret: Data(repeating: 0, count: 32), intentDigest: Data(repeating: 3, count: 32), proof: Data([1])))
    }
}
