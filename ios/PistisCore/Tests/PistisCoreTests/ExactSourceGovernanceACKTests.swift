import Foundation
import XCTest
@testable import PistisCore

/// Closed public task conformance. These comparison originals authenticate no
/// current server role, device, native owner or physical Face ID operation.
final class ExactSourceGovernanceACKTests: XCTestCase {
    private func encode(_ value: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes])
    }
    private func digest(_ value: Data) -> String { IssuerPhoneWire.sha256(value).map { String(format: "%02x",$0) }.joined() }
    private func fixture() throws -> (body: [String: Any], originals: [Data]) {
        let verdict = Data("independent original review comparison DATA".utf8)
        let admission = Data("{\"public\":\"admission-intent DATA\"}".utf8)
        let role = Data("original native role comparison DATA; not authority".utf8)
        let source = try encode(["schema":"mnemosyne.proxenos.exact-source-owner-successor.v1", "repository":"https://github.com/sagrudd/pistis", "repository_id":1310759408, "pull_request":526, "review_ref":"refs/pull/526/head", "reviewed_revision":"bddfb43676a709134d040c84828fcd0ae9c7812d", "reviewed_tree":"187fae055997ff845ba7637208271c8c0c666037", "owner_id":3848500, "owner_login":"sagrudd", "owner_record_id":UInt64(6255076636), "owner_record_created_at":"2026-10-18T20:59:29Z", "owner_record_updated_at":"2026-10-18T20:59:29Z", "owner_record_body":"INT-07 exact-source owner successor disposition\nRepository: sagrudd/pistis (GitHub repository ID 1310759408).\nPull request: 526; review ref: refs/pull/526/head.\nSelected commit: bddfb43676a709134d040c84828fcd0ae9c7812d.\nSelected tree: 187fae055997ff845ba7637208271c8c0c666037.\nPredecessor: b1da78b06ac0f66756c22e2aeeaec0a0ed762364; its earlier acceptance does not cover this successor.\nI, Stephen Rudd, explicitly adopt OFFLINE_SOURCE_REVIEW.json, SHA-256 2f43bbce74c747055e17c5d8181cb2a3f9f9d0b9fa466c8e0f0b4fca28409238, together with its exact publication mapping OFFLINE_FINAL_PUBLISHED_REVIEW.json, SHA-256 845e090bdc78681e6d124219057f0e8ef97af5037111172fdb10dcbba5e10d7e, for this selected source. The adopted review covers the three-file offline-input CI successor and preserves the recorded scope of prior unchanged-source evidence; it is not a genuine CI or full-runtime pass.\nThis explicit owner successor disposition clears EXTERNAL:INT-07.05 for this commit/tree only. It records my earlier exact final source-review acceptance at call202a96a458574dbeae7db696a6412784; the present explicit adoption is independently verifiable from this owner-authored record.\nConditions: preserve the adopted artifact bytes and all disclosed partial-history/qualification limits. Any changed source, changed/deleted/revoked disposition or unmet condition requires fresh disposition. Genuine required Jenkins/Expedition evidence, exact final Kanon binding and normal protected merge remain required. This grants no local admission/configuration acceptance, installation, activation, signing, custody, phone or provider authority.\n", "owner_record_sha256":"b969a230f62b722856fa14e4c9319f1386c6cfe27bf7e63ad460cc949d3becd0", "policy_sha256":"b18435a596622b959703bd538a8b32da229996582d88e793ccd9caec61ec99ff", "original_independent_technical_review_sha256":digest(verdict)])
        let install="11111111-1111-4111-8111-111111111111", site="22222222-2222-4222-8222-222222222222", target=String(repeating:"e",count:64)
        let subject = try encode(["schema":"mnemosyne.proxenos.exact-source-technical-review.v1", "mode":"recorded-owner-exception", "installation_id":install, "site_uuid":site, "admission_intent_sha256":digest(admission), "repository":"https://github.com/sagrudd/pistis", "source_revision":"bddfb43676a709134d040c84828fcd0ae9c7812d", "source_tree_revision":"187fae055997ff845ba7637208271c8c0c666037", "original_review_sha256":digest(verdict), "verdict":"pass", "scope":"exact-source-authority-origin", "reviewer_subject":"prosopikon:original-owner", "reviewer_device_target":target, "reviewer_device_generation":"1", "issued_at":"100", "expires_at":"160", "nonce":String(repeating:"d",count:64)])
        var body:[String:Any] = ["schema":"mnemosyne.proxenos.exact-source-governance-witness.v1", "disposition":"active-owner-exception", "installation_id":install, "site_uuid":site, "employee_count":1, "external_customer_use":false, "policy_sha256":"b18435a596622b959703bd538a8b32da229996582d88e793ccd9caec61ec99ff", "canonical_governance_source_sha256":digest(source), "review_subject_sha256":digest(subject), "owner_subject":"prosopikon:original-owner", "owner_device_target":target, "owner_device_generation":"1", "issued_at":"100", "expires_at":"160", "nonce":String(repeating:"f",count:64)]
        let action = try encode(["operation":"exact_source_role_decision", "purpose":"governance-exception", "audience":"jenkins", "action_body_sha256":digest(encode(body)), "admission_binding_sha256":digest(admission), "installation_id":install, "site_uuid":site, "challenge":String(repeating:"a",count:64), "issued_at":"100", "expires_at":"160"])
        body["role_decision_sha256"]=digest(role)
        return (body,[role,action,admission,subject,source,verdict])
    }
    private func task(_ body:[String:Any], _ originals:[Data], kind:UInt64=3, expiry:UInt64=155) throws -> Data {
        try IssuerCBOR.array([.unsigned(1),.bytes(Data("exact-source-ack-task-v1".utf8)),.bytes(Data(repeating:2,count:16)),.bytes(Data(repeating:1,count:32)),.unsigned(kind),.bytes(encode(body)),.array(originals.map{.bytes($0)}),.unsigned(expiry)]).encoded()
    }
    func testGovernanceUsesExactExistingBodyAndDistinctKindThree() throws {
        let f=try fixture(), nonce=Data(repeating:1,count:32)
        let parsed=try ExactSourceACKWire.task(task(f.body,f.originals),challenge:nonce,kind:.governance,now:150)
        XCTAssertEqual(parsed.body.kind,.governance)
        XCTAssertEqual(parsed.originals,f.originals)
        XCTAssertThrowsError(try ExactSourceACKWire.task(task(f.body,f.originals,kind:2),challenge:nonce,kind:.governance,now:150))
        XCTAssertThrowsError(try ExactSourceACKWire.task(task(f.body,f.originals),challenge:nonce,kind:.technicalReview,now:150))
        XCTAssertThrowsError(try ExactSourceACKWire.task(task(f.body,f.originals,expiry:161),challenge:nonce,kind:.governance,now:150))
    }
    func testGovernanceDeniesChangedPolicyScalarTypesUsageAndRoleGraph() throws {
        let f=try fixture()
        for (field,value) in [("employee_count",2 as Any),("employee_count","1" as Any),("external_customer_use",true as Any),("external_customer_use","false" as Any),("policy_sha256",String(repeating:"a",count:64) as Any),("owner_device_generation","0" as Any)] {
            var body=f.body;body[field]=value
            XCTAssertThrowsError(try ExactSourceACKBody.parse(encode(body),now:150),field)
        }
        for index in 0..<f.originals.count {
            var originals=f.originals;originals[index].append(32)
            XCTAssertThrowsError(try ExactSourceACKWire.task(task(f.body,originals),challenge:Data(repeating:1,count:32),kind:.governance,now:150),"changed original \(index)")
        }
        var wrong=f.originals
        var action=try JSONSerialization.jsonObject(with:wrong[1]) as! [String:String]
        action["purpose"]="technical-review";wrong[1]=try encode(action)
        XCTAssertThrowsError(try ExactSourceACKWire.task(task(f.body,wrong),challenge:Data(repeating:1,count:32),kind:.governance,now:150))
    }
    func testGovernanceDuplicateUnknownAndExpiredBodiesNeverReachTask() throws {
        let f=try fixture();let raw=try encode(f.body)
        var duplicate=Data("{\"employee_count\":1,".utf8);duplicate.append(raw.dropFirst())
        XCTAssertThrowsError(try ExactSourceACKBody.parse(duplicate,now:150))
        var unknown=f.body;unknown["approved"]=true
        XCTAssertThrowsError(try ExactSourceACKBody.parse(encode(unknown),now:150))
        XCTAssertThrowsError(try ExactSourceACKBody.parse(raw,now:160))
    }
}
