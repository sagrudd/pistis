import Foundation
import XCTest
@testable import PistisApp

final class MTGSRecoveryPresentationTests: XCTestCase {
    private let origin = URL(string: "https://monas.example.test")!

    func testAcceptsExactPinnedRecoveryInvitation() throws {
        let value = try MTGSRecoveryPresentationV1(
            qrText: invitation(), pinnedAuthorityOrigin: origin, nowUnixSeconds: 1_050
        )
        XCTAssertEqual(value.reference, "mtgs-recovery-1234")
        XCTAssertEqual(value.siteTrustDomain, "site-1234")
        XCTAssertEqual(value.authorityOrigin, origin)
        XCTAssertEqual(value.ceremonyID, Data(repeating: 1, count: 16))
        XCTAssertEqual(value.challengeDigest, Data(repeating: 2, count: 32))
        XCTAssertEqual(value.keyID, Data(repeating: 3, count: 32))
    }

    func testAcceptsExactMonasConformanceFixture() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../../../fixtures/mtgs-recovery/presentation-v1.json")
        let text = try String(contentsOf: url, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let value = try MTGSRecoveryPresentationV1(
            qrText: text, pinnedAuthorityOrigin: origin, nowUnixSeconds: 1_050
        )
        XCTAssertEqual(value.siteTrustDomain, "site-00000001")
        XCTAssertEqual(value.reference, "mtgs-recovery-fixture")
    }

    func testRejectsWrongAudienceEndpointOriginExpiryAndUnknownFields() {
        let mutations = [
            invitation().replacingOccurrences(
                of: MTGSRecoveryPresentationV1.audience, with: "monas-local"
            ),
            invitation().replacingOccurrences(
                of: "https://monas.example.test", with: "https://attacker.example"
            ),
            invitation().replacingOccurrences(
                of: "\"expires_at_unix_seconds\":1100",
                with: "\"expires_at_unix_seconds\":1050"
            ),
            String(invitation().dropLast()) + ",\"submit_url\":\"https://attacker.example\"}",
        ]
        for mutation in mutations {
            XCTAssertThrowsError(try MTGSRecoveryPresentationV1(
                qrText: mutation, pinnedAuthorityOrigin: origin, nowUnixSeconds: 1_050
            ))
        }
    }

    func testRejectsNonCanonicalBase64AndOverlongLifetime() {
        XCTAssertThrowsError(try MTGSRecoveryPresentationV1(
            qrText: invitation().replacingOccurrences(
                of: encoded(Data(repeating: 1, count: 16)),
                with: encoded(Data(repeating: 1, count: 16)) + "="
            ), pinnedAuthorityOrigin: origin, nowUnixSeconds: 1_050
        ))
        XCTAssertThrowsError(try MTGSRecoveryPresentationV1(
            qrText: invitation().replacingOccurrences(
                of: "\"expires_at_unix_seconds\":1100",
                with: "\"expires_at_unix_seconds\":2000"
            ), pinnedAuthorityOrigin: origin, nowUnixSeconds: 1_050
        ))
    }

    private func invitation() -> String {
        """
        {"app_identifier":"C7A6NQTSY4.org.mnemosynebiosciences.pistis","audience":"monas:site-trust:mtgs-recovery:v1","authority_origin":"https://monas.example.test","ceremony_id_b64url":"\(encoded(Data(repeating: 1, count: 16)))","challenge_digest_b64url":"\(encoded(Data(repeating: 2, count: 32)))","expires_at_unix_seconds":1100,"issued_at_unix_seconds":1000,"key_id_b64url":"\(encoded(Data(repeating: 3, count: 32)))","reference":"mtgs-recovery-1234","schema":"monas.site-trust-mtgs-recovery-presentation.v1","site_trust_domain":"site-1234"}
        """
    }

    private func encoded(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
