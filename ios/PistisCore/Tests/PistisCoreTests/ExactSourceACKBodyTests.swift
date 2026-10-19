import Foundation
import XCTest
@testable import PistisCore

final class ExactSourceACKBodyTests: XCTestCase {
    private func review() -> [String: String] {
        let digest = String(repeating: "a", count: 64)
        return ["schema":"mnemosyne.proxenos.exact-source-technical-review.v1", "mode":"independent-subject", "installation_id":"11111111-1111-4111-8111-111111111111", "site_uuid":"22222222-2222-4222-8222-222222222222", "admission_intent_sha256":digest, "repository":"https://github.com/sagrudd/pistis", "source_revision":String(repeating:"b",count:40), "source_tree_revision":String(repeating:"c",count:40), "original_review_sha256":digest, "verdict":"pass", "scope":"exact-source-authority-origin", "reviewer_subject":"prosopikon:reviewer", "reviewer_device_target":digest, "reviewer_device_generation":"1", "reviewer_role_decision_sha256":digest, "governance_witness_sha256":digest, "owner_approval_merge_witness_sha256":digest, "issued_at":"100", "expires_at":"200", "nonce":digest]
    }
    private func encode(_ object: [String:String]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    func testClosedReviewOriginalParsesWithoutCreatingAuthority() throws {
        let raw = try encode(review())
        let data = try ExactSourceACKBody.parse(raw, now: 150)
        XCTAssertEqual(data.kind, .technicalReview)
        XCTAssertEqual(data.original, raw)
        XCTAssertThrowsError(try ExactSourceACKBody.parse(raw, now: 200))
    }
    func testDuplicateUnknownNoncanonicalAndMalformedGenerationDeny() throws {
        let raw = try encode(review())
        var duplicate = Data("{\"schema\":\"duplicate\",".utf8); duplicate.append(raw.dropFirst())
        XCTAssertThrowsError(try ExactSourceACKBody.parse(duplicate, now: 150))
        var unknown = review(); unknown["approved"] = "true"
        XCTAssertThrowsError(try ExactSourceACKBody.parse(encode(unknown), now: 150))
        XCTAssertThrowsError(try ExactSourceACKBody.parse(Data(" ".utf8) + raw, now: 150))
        for bad in ["0", "01", "18446744073709551616"] {
            var value = review(); value["reviewer_device_generation"] = bad
            XCTAssertThrowsError(try ExactSourceACKBody.parse(encode(value), now: 150))
        }
    }
    func testPrivateTaskTransportCorrelationRejectsWrongModeAndUnknownFrame() throws {
        let request = try ExactSourceACKWire.prepare(challenge: Data(repeating:1,count:32), kind: .enrollment, target: Data(repeating:2,count:32), generation:1)
        XCTAssertFalse(request.isEmpty)
        XCTAssertThrowsError(try ExactSourceACKWire.prepare(challenge:Data(repeating:0,count:32),kind:.enrollment,target:Data(repeating:2,count:32),generation:1))
        XCTAssertThrowsError(try ExactSourceACKWire.task(request,challenge:Data(repeating:1,count:32),kind:.enrollment,now:150))
    }
    func testReviewTaskUsesSixGenuineOriginalsAndFullAcyclicActionGraph() throws {
        func digest(_ value: Data) -> String { IssuerPhoneWire.sha256(value).map { String(format:"%02x",$0) }.joined() }
        let role = Data("role-original-comparison".utf8)
        let admission = Data("{\"draft-admission-intent\":\"comparison\"}".utf8)
        let verdict = Data("independent-original-verdict".utf8)
        let governance = Data("canonical-governance-comparison".utf8)
        let owner = Data("owner-merge-comparison".utf8)
        var body = review()
        body["reviewer_role_decision_sha256"] = digest(role)
        body["admission_intent_sha256"] = digest(admission)
        body["original_review_sha256"] = digest(verdict)
        body["governance_witness_sha256"] = digest(governance)
        body["owner_approval_merge_witness_sha256"] = digest(owner)
        var intent = body; intent.removeValue(forKey:"reviewer_role_decision_sha256")
        var action = ["operation":"exact_source_role_decision", "purpose":"technical-review", "audience":"jenkins", "action_body_sha256":digest(try encode(intent)), "admission_binding_sha256":digest(admission), "installation_id":body["installation_id"]!, "site_uuid":body["site_uuid"]!, "challenge":String(repeating:"d",count:64), "issued_at":"100", "expires_at":"160"]
        func task(_ action: [String:String], expiry: UInt64 = 155) throws -> Data {
            try IssuerCBOR.array([.unsigned(1),.bytes(Data("exact-source-ack-task-v1".utf8)),.bytes(Data(repeating:2,count:16)),.bytes(Data(repeating:1,count:32)),.unsigned(2),.bytes(encode(body)),.array([role,try encode(action),admission,verdict,governance,owner].map { .bytes($0) }),.unsigned(expiry)]).encoded()
        }
        let raw = try task(action)
        let parsed = try ExactSourceACKWire.task(raw,challenge:Data(repeating:1,count:32),kind:.technicalReview,now:150)
        XCTAssertEqual(parsed.originals.count,6)
        XCTAssertEqual(parsed.originals[3],verdict)
        XCTAssertThrowsError(try ExactSourceACKWire.task(task(action,expiry:161),challenge:Data(repeating:1,count:32),kind:.technicalReview,now:150))
        action["action_body_sha256"] = String(repeating:"f",count:64)
        XCTAssertThrowsError(try ExactSourceACKWire.task(task(action),challenge:Data(repeating:1,count:32),kind:.technicalReview,now:150))
    }

    func testPendingReviewReceiptIsCorrelatedPublicDataAndCannotBecomeTask() throws {
        let nonce = Data(repeating: 3, count: 32)
        func packet(_ challenge: Data, _ end: UInt64) throws -> Data {
            try IssuerCBOR.array([.unsigned(1), .bytes(Data("exact-source-ack-review-witnesses-pending-v1".utf8)),
                .bytes(Data(repeating: 1, count: 16)), .bytes(challenge),
                .bytes(Data(repeating: 2, count: 32)), .unsigned(end)]).encoded()
        }
        let raw = try packet(nonce, 120)
        XCTAssertEqual(try ExactSourceACKWire.pendingReview(raw, challenge: nonce, now: 100)?.expiresAt, 120)
        XCTAssertThrowsError(try ExactSourceACKWire.pendingReview(raw, challenge: Data(repeating: 4, count: 32), now: 100))
        XCTAssertThrowsError(try ExactSourceACKWire.pendingReview(packet(nonce, 120), challenge: nonce, now: 120))
        XCTAssertThrowsError(try ExactSourceACKWire.pendingReview(packet(nonce, 131), challenge: nonce, now: 100))
        XCTAssertThrowsError(try ExactSourceACKWire.task(raw, challenge: nonce, kind: .technicalReview, now: 100))
    }

    func testPendingSubjectDigestIncludesIdentityAndExcludesOnlyThreeLateDigests() throws {
        var fields = review()
        let first = try ExactSourceACKWire.reviewSubjectDigest(ExactSourceACKBody.parse(encode(fields), now: 150))
        fields["reviewer_role_decision_sha256"] = String(repeating: "d", count: 64)
        fields["governance_witness_sha256"] = String(repeating: "e", count: 64)
        fields["owner_approval_merge_witness_sha256"] = String(repeating: "f", count: 64)
        XCTAssertEqual(first, try ExactSourceACKWire.reviewSubjectDigest(ExactSourceACKBody.parse(encode(fields), now: 150)))
        fields["nonce"] = String(repeating: "b", count: 64)
        XCTAssertNotEqual(first, try ExactSourceACKWire.reviewSubjectDigest(ExactSourceACKBody.parse(encode(fields), now: 150)))
    }

}
