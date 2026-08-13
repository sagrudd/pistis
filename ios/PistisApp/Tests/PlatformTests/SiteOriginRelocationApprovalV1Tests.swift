import CryptoKit
import Foundation
import XCTest

@testable import Pistis

final class SiteOriginRelocationApprovalV1Tests: XCTestCase {
    func testExactCanonicalProposalDisplaysAllAuthorityBindings() throws {
        let fixture = RelocationFixture()
        let value = try fixture.presentation()
        XCTAssertEqual(value.sourceOrigin.absoluteString, "https://192.168.1.192:8443/")
        XCTAssertEqual(value.targetOrigin.absoluteString, "https://192.168.0.193:8443/")
        XCTAssertEqual(value.siteTrustDomain, "site-demo")
        XCTAssertEqual(value.authorityGeneration, "authority-1")
        XCTAssertEqual(value.custodyGeneration, "custody-1")
        XCTAssertEqual(value.siteRootGeneration, "root-1")
        XCTAssertEqual(value.issuingCAGeneration, "issuer-1")
    }

    func testPurposeAudienceTargetExpiryAndUnknownFieldsDeny() throws {
        var fixture = RelocationFixture()
        fixture.fields[2] = Data("browser:generic".utf8); fixture.refresh()
        XCTAssertThrowsError(try fixture.presentation())
        fixture = RelocationFixture()
        fixture.fields[6] = Data("https://monas.local:8443/".utf8); fixture.refresh()
        XCTAssertThrowsError(try fixture.presentation())
        fixture = RelocationFixture()
        fixture.object["fallback_url"] = "https://192.168.0.193:8443/"
        XCTAssertThrowsError(try fixture.presentation())
        XCTAssertThrowsError(try RelocationFixture().presentation(now: 1_200))
    }

    func testReorderedTrailingDigestSubstitutionAndAlternateBase64Deny() throws {
        var fixture = RelocationFixture()
        fixture.tags[4] = 6; fixture.refresh()
        XCTAssertThrowsError(try fixture.presentation())
        fixture = RelocationFixture()
        fixture.payload.append(0); fixture.refreshWrapper()
        XCTAssertThrowsError(try fixture.presentation())
        fixture = RelocationFixture()
        fixture.object["proposal_sha256_b64url"] = RelocationFixture.b64url(Data(repeating: 9, count: 32))
        XCTAssertThrowsError(try fixture.presentation())
        fixture = RelocationFixture()
        fixture.object["proposal_sha256_b64url"] = fixture.object["proposal_sha256_b64url"] as! String + "="
        XCTAssertThrowsError(try fixture.presentation())
    }

    func testClientDataHashBindsSignatureAndEveryFixedIdentity() throws {
        let value = try RelocationFixture().presentation()
        let first = try value.clientDataHash(siteAuthoritySignatureSHA256: Data(repeating: 7, count: 32))
        let changed = try value.clientDataHash(siteAuthoritySignatureSHA256: Data(repeating: 8, count: 32))
        XCTAssertNotEqual(first, changed)
        var expected = SiteOriginRelocationProfileV1.clientDataDomain
        expected += value.installationID + value.appAttestKeyID + value.proposalDigest
            + value.ceremonyID + value.challengeDigest + Data(repeating: 7, count: 32)
        XCTAssertEqual(first, Data(SHA256.hash(data: expected)))
    }

    func testStatusBindsExactCeremonyDigestAndClosedState() throws {
        let value = try RelocationFixture().presentation()
        let valid: [String: Any] = [
            "schema": SiteOriginRelocationProfileV1.statusSchema,
            "ceremony_id_b64url": RelocationFixture.b64url(value.ceremonyID),
            "proposal_sha256_b64url": RelocationFixture.b64url(value.proposalDigest),
            "state": "approved",
        ]
        XCTAssertEqual(try SiteOriginRelocationStatusV1(
            data: JSONSerialization.data(withJSONObject: valid), expected: value
        ).state, .approved)
        var replay = valid; replay["proposal_sha256_b64url"] = RelocationFixture.b64url(Data(repeating: 9, count: 32))
        XCTAssertThrowsError(try SiteOriginRelocationStatusV1(
            data: JSONSerialization.data(withJSONObject: replay), expected: value
        ))
        var invented = valid; invented["state"] = "rolled_back"
        XCTAssertThrowsError(try SiteOriginRelocationStatusV1(
            data: JSONSerialization.data(withJSONObject: invented), expected: value
        ))
    }
}

private struct RelocationFixture {
    var fields: [Data]
    var tags = Array(UInt8(1) ... UInt8(20))
    var payload = Data()
    var object: [String: Any] = [:]

    init() {
        func u64(_ value: UInt64) -> Data { withUnsafeBytes(of: value.bigEndian) { Data($0) } }
        fields = [
            Data(SiteOriginRelocationProfileV1.purpose.utf8),
            Data(SiteOriginRelocationProfileV1.purpose.utf8),
            Data(SiteOriginRelocationProfileV1.audience.utf8), Data(repeating: 1, count: 16),
            Data("site-demo".utf8), Data("https://192.168.1.192:8443/".utf8),
            Data("https://192.168.0.193:8443/".utf8), u64(1), u64(2),
            Data("authority-1".utf8), Data("custody-1".utf8), Data("root-1".utf8),
            Data("issuer-1".utf8), Data("service-monas-web".utf8),
            Data("192.168.0.193".utf8), Data(repeating: 2, count: 16),
            Data(repeating: 3, count: 32), u64(900), u64(1_200), Data(repeating: 4, count: 32),
        ]
        refresh()
    }

    mutating func refresh() {
        payload = Data("PXSR/v1\0".utf8)
        for (tag, field) in zip(tags, fields) {
            payload.append(tag); payload.append(UInt8(field.count >> 8)); payload.append(UInt8(field.count & 0xff)); payload += field
        }
        refreshWrapper()
    }
    mutating func refreshWrapper() {
        object = [
            "schema": SiteOriginRelocationProfileV1.presentationSchema,
            "canonical_proposal_b64": payload.base64EncodedString(),
            "proposal_sha256_b64url": Self.b64url(Data(SHA256.hash(data: payload))),
            "installation_id_b64url": Self.b64url(Data(repeating: 5, count: 16)),
            "app_attest_key_id_b64url": Self.b64url(Data(repeating: 6, count: 32)),
            "state": "prepared", "warning": SiteOriginRelocationProfileV1.warning,
        ]
    }
    func presentation(now: UInt64 = 1_000) throws -> SiteOriginRelocationPresentationV1 {
        try SiteOriginRelocationPresentationV1(
            qrText: String(data: JSONSerialization.data(withJSONObject: object), encoding: .utf8)!,
            nowUnixSeconds: now
        )
    }
    static func b64url(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
