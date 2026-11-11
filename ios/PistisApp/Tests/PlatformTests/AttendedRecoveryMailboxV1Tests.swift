import Foundation
import CryptoKit
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
        for badCache in ["x-no-store", "no-store=false"] {
            let invalid = try XCTUnwrap(HTTPURLResponse(url: AttendedRecoveryMailboxV1.endpoint, statusCode: 200,
                httpVersion: nil, headerFields: ["Content-Type": "application/json", "Cache-Control": badCache]))
            XCTAssertThrowsError(try AttendedRecoveryMailboxV1.validateReceipt(data, response: invalid))
        }
    }
    func testRejectsOversizedProofAndInvalidCapability() {
        XCTAssertThrowsError(try AttendedRecoveryMailboxV1.request(requestID: Data(repeating: 1, count: 16), relaySecret: Data(repeating: 2, count: 32), intentDigest: Data(repeating: 3, count: 32), proof: Data(repeating: 1, count: 8_193)))
        XCTAssertThrowsError(try AttendedRecoveryMailboxV1.request(requestID: Data(repeating: 1, count: 16), relaySecret: Data(repeating: 0, count: 32), intentDigest: Data(repeating: 3, count: 32), proof: Data([1])))
    }
    func testProvisionalSuccessorPhaseEnvelopesAndClosedResponses() throws {
        let id = Data(repeating: 1, count: 16), secret = Data(repeating: 2, count: 32)
        let payload = Data(repeating: 7, count: 16_384)
        let digest = Data(SHA256.hash(data: payload))
        let poll = try AttendedRecoveryPhaseWireV1.poll(requestID: id, capability: secret, phase: .rootUnlock)
        XCTAssertEqual(poll.url, AttendedRecoveryPhaseWireV1.pollEndpoint)
        let request = try AttendedRecoveryPhaseWireV1.submit(requestID: id, capability: secret, phase: .rootUnlock, presentationDigest: digest, submission: payload)
        XCTAssertLessThanOrEqual(try XCTUnwrap(request.httpBody).count, 32_768)
        let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: String])
        XCTAssertEqual(Set(fields.keys), ["schema", "request_id_b64url", "phone_capability_b64url", "phase", "presentation_sha256_b64url", "submission_b64url"])
        let headers = ["Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store"]
        let response = try XCTUnwrap(HTTPURLResponse(url: AttendedRecoveryPhaseWireV1.pollEndpoint, statusCode: 200, httpVersion: nil, headerFields: headers))
        let object = ["schema": "mnemosyne.monas.first-install-broker.response.v1", "state": "ready", "presentation_b64url": SiteRootBrokerPresentationV2.encode(payload), "presentation_sha256_b64url": SiteRootBrokerPresentationV2.encode(digest)]
        XCTAssertEqual(try AttendedRecoveryPhaseWireV1.pollResponse(JSONSerialization.data(withJSONObject: object), response: response), .ready(payload))
        var wrong = object; wrong["presentation_sha256_b64url"] = SiteRootBrokerPresentationV2.encode(Data(repeating: 1, count: 32))
        XCTAssertThrowsError(try AttendedRecoveryPhaseWireV1.pollResponse(JSONSerialization.data(withJSONObject: wrong), response: response))
        wrong = object; wrong["extra"] = "x"
        XCTAssertThrowsError(try AttendedRecoveryPhaseWireV1.pollResponse(JSONSerialization.data(withJSONObject: wrong), response: response))
        XCTAssertThrowsError(try AttendedRecoveryPhaseWireV1.submit(requestID: id, capability: secret, phase: .rootUnlock, presentationDigest: digest, submission: payload + Data([1])))
        XCTAssertThrowsError(try AttendedRecoveryPhaseWireV1.poll(requestID: id, capability: Data(repeating: 0, count: 32), phase: .rootUnlock))
        let accepted = try XCTUnwrap(HTTPURLResponse(url: AttendedRecoveryPhaseWireV1.submitEndpoint, statusCode: 202, httpVersion: nil, headerFields: headers))
        XCTAssertNoThrow(try AttendedRecoveryPhaseWireV1.submissionReceipt(Data(#"{"schema":"mnemosyne.monas.first-install-broker.response.v1","state":"submitted"}"#.utf8), response: accepted))
    }

}
