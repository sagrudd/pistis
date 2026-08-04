import Foundation
import XCTest
@testable import Pistis

final class SiteRootDelegationProofTests: XCTestCase {
    func testPresentationAcceptsOnlyExactV1Bindings() throws {
        let payload = Data("{\"device_key_id\":\"site-root-fixture\",\"proof_profile\":\"pistis-secure-enclave-es256-cose-v1\",\"schema\":\"monas.site-root-delegation.v1\",\"secure_enclave_attestation\":\"not-asserted\"}".utf8)
        let endpoint = try XCTUnwrap(URL(string: "https://monas.example.test/auth/pistis/site-root-delegations/v1/submit"))
        let presentation = try SiteRootDelegationPresentationV1(
            canonicalDelegationJSON: payload,
            deviceKeyID: "site-root-fixture",
            submitURL: endpoint,
            reference: "ceremony-fixture"
        )
        XCTAssertEqual(presentation.canonicalDelegationJSON, payload)
        XCTAssertThrowsError(try SiteRootDelegationPresentationV1(
            canonicalDelegationJSON: payload,
            deviceKeyID: "site-root-fixture",
            submitURL: try XCTUnwrap(URL(string: "https://monas.example.test/other")),
            reference: "ceremony-fixture"
        ))
    }

    func testDetachedCoseEnvelopeHasNullPayloadAndNoUnprotectedHeaders() throws {
        let protected = try DetachedES256Cose.protectedHeaders(kid: "site-root-fixture")
        let structure = try DetachedES256Cose.signatureStructure(protected: protected, payload: Data("{}".utf8))
        XCTAssertEqual(structure.first, 0x84)
        XCTAssertTrue(structure.contains(Data("Signature1".utf8)))
        let signature = Data([1] + Array(repeating: 0, count: 31) + Array(repeating: 0, count: 31) + [1])
        let envelope = try DetachedES256Cose.envelope(protected: protected, signature: signature)
        XCTAssertEqual(envelope.first, 0x84)
        XCTAssertTrue(envelope.contains(Data([0xa0, 0xf6])))
    }

    func testDetachedCoseRejectsHighSSignature() throws {
        let protected = try DetachedES256Cose.protectedHeaders(kid: "site-root-fixture")
        let highS = Data([1] + Array(repeating: 0, count: 31) + Array(repeating: 0xff, count: 32))
        XCTAssertThrowsError(try DetachedES256Cose.envelope(protected: protected, signature: highS))
    }

    func testQRPresentationAcceptsOnlyExactWrapperAndPreservesDelegationBytes() throws {
        let delegation = Data("{\"device_key_id\":\"site-root-fixture\",\"proof_profile\":\"pistis-secure-enclave-es256-cose-v1\",\"schema\":\"monas.site-root-delegation.v1\",\"secure_enclave_attestation\":\"not-asserted\"}".utf8)
        let base64URL = delegation.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let qr = "{\"canonical_delegation_base64url\":\"\(base64URL)\",\"device_key_id\":\"site-root-fixture\",\"reference\":\"ceremony-fixture-1234\",\"schema\":\"monas.site-root-delegation-presentation.v1\",\"submit_url\":\"https://monas.example.test/auth/pistis/site-root-delegations/v1/submit\"}"

        let parsed = try SiteRootDelegationQRPresentationV1(qrText: qr)

        XCTAssertEqual(parsed.presentation.canonicalDelegationJSON, delegation)
        XCTAssertEqual(parsed.presentation.reference, "ceremony-fixture-1234")
        XCTAssertThrowsError(try SiteRootDelegationQRPresentationV1(qrText: String(qr.dropLast()) + "x"))
        XCTAssertThrowsError(try SiteRootDelegationQRPresentationV1(
            qrText: String(qr.dropLast()) + ",\"extra\":true}"
        ))
    }

    func testReviewRedactsIdentifiers() throws {
        let presentation = try SiteRootDelegationPresentationV1(
            canonicalDelegationJSON: Data("{\"device_key_id\":\"site-root-fixture\",\"proof_profile\":\"pistis-secure-enclave-es256-cose-v1\",\"schema\":\"monas.site-root-delegation.v1\",\"secure_enclave_attestation\":\"not-asserted\"}".utf8),
            deviceKeyID: "site-root-fixture",
            submitURL: try XCTUnwrap(URL(string: "https://monas.example.test/auth/pistis/site-root-delegations/v1/submit")),
            reference: "ceremony-fixture-1234"
        )

        let review = SiteRootDelegationReview(presentation: presentation)

        XCTAssertFalse(review.reference.contains("fixture-1234"))
        XCTAssertFalse(review.deviceKeyFingerprint.contains("root-fixture"))
        XCTAssertEqual(review.destination, "monas.example.test")
    }
}
