import Foundation
import XCTest
@testable import Pistis

final class SiteRootConvergenceProtocolTests: XCTestCase {
    private let nowSeconds: UInt64 = 1_900_000_000

    func testBundleReceiptPresentationBindsExactPurposeSiteGenerationAndDevice() throws {
        let challenge = provisionChallenge(site: "site-demo", generation: 7)
        let qr = json([
            "schema": SiteRootConvergenceProfileV2.provisionSchema,
            "purpose": SiteRootConvergenceProfileV2.provisionPurpose,
            "correlation_b64url": b64(Data(repeating: 1, count: 16)),
            "canonical_challenge_b64url": b64(challenge),
            "site_trust_domain": "site-demo",
            "receipt_key_generation": 7,
            "expires_at_unix_seconds": nowSeconds + 120,
            "submission_path": SiteRootConvergenceProfileV2.provisionPath,
        ])
        let value = try SiteRootBundleReceiptProvisionPresentationV1(
            qrText: qr, nowUnixSeconds: nowSeconds
        )
        XCTAssertNoThrow(try value.validateChallenge(deviceKeyID: "site-root-device"))
        XCTAssertThrowsError(try value.validateChallenge(deviceKeyID: "site-root-other"))
    }

    func testBundleReceiptRejectsExpiryAndUnknownMember() throws {
        var object: [String: Any] = [
            "schema": SiteRootConvergenceProfileV2.provisionSchema,
            "purpose": SiteRootConvergenceProfileV2.provisionPurpose,
            "correlation_b64url": b64(Data(repeating: 1, count: 16)),
            "canonical_challenge_b64url": b64(provisionChallenge(site: "site-demo", generation: 7)),
            "site_trust_domain": "site-demo", "receipt_key_generation": 7,
            "expires_at_unix_seconds": nowSeconds,
            "submission_path": SiteRootConvergenceProfileV2.provisionPath,
        ]
        XCTAssertThrowsError(try SiteRootBundleReceiptProvisionPresentationV1(
            qrText: json(object), nowUnixSeconds: nowSeconds
        ))
        object["expires_at_unix_seconds"] = nowSeconds + 60
        object["fallback"] = true
        XCTAssertThrowsError(try SiteRootBundleReceiptProvisionPresentationV1(
            qrText: json(object), nowUnixSeconds: nowSeconds
        ))
    }

    func testPXRAExactFrameParsesAndDriftFailsClosed() throws {
        let unsigned = pxra()
        let origin = URL(string: "https://192.168.1.192:8443")!
        let qr = json([
            "schema": SiteRootConvergenceProfileV2.ackSchema,
            "purpose": SiteRootConvergenceProfileV2.ackPurpose,
            "unsigned_pxra_v2_b64url": b64(unsigned),
            "submission_url": origin.absoluteString
                + SiteRootConvergenceProfileV2.ackSubmissionPath,
        ])
        let value = try SiteRootConvergenceAckPresentationV2(
            qrText: qr, authorityOrigin: origin,
            nowUnixMilliseconds: nowSeconds * 1_000
        )
        XCTAssertEqual(value.assertion.siteUUIDText, "01010101-0101-0101-0101-010101010101")
        XCTAssertEqual(value.assertion.action, .install)
        XCTAssertEqual(value.assertion.ackKeyGeneration, 3)

        var trailing = unsigned
        trailing.append(0)
        XCTAssertThrowsError(try UnsignedSiteRootConvergenceAssertionV2(
            trailing, nowUnixMilliseconds: nowSeconds * 1_000
        ))
    }

    func testSiteX509PresentationBindsAtomicDistinctRoles() throws {
        let site = Data(repeating: 2, count: 16)
        let transaction = Data(repeating: 3, count: 16)
        let challenge = x509Challenge(
            site: site, transaction: transaction, generation: 4
        )
        let qr = json([
            "schema": SiteRootConvergenceProfileV2.x509ProvisionSchema,
            "purpose": SiteRootConvergenceProfileV2.x509Purpose,
            "site_uuid": "02020202-0202-0202-0202-020202020202",
            "transaction_uuid": "03030303-0303-0303-0303-030303030303",
            "generation": 4,
            "canonical_challenge_b64url": b64(challenge),
            "roles": SiteX509FirstProvisionPresentationV1.roles,
            "expires_at_unix_seconds": nowSeconds + 120,
            "submission_path": SiteRootConvergenceProfileV2.x509SubmitPath,
        ])
        XCTAssertNoThrow(try SiteX509FirstProvisionPresentationV1(
            qrText: qr, nowUnixSeconds: nowSeconds
        ))

        var drift = try JSONSerialization.jsonObject(with: Data(qr.utf8)) as! [String: Any]
        drift["roles"] = ["site-x509-issuer", "site-x509-root"]
        XCTAssertThrowsError(try SiteX509FirstProvisionPresentationV1(
            qrText: json(drift), nowUnixSeconds: nowSeconds
        ))
    }

    func testPurposeSpecificProtectedHeadersAreCanonical() throws {
        let kid = Data(repeating: 9, count: 8)
        let contentType = SiteRootConvergenceProfileV2.pxraContentType
        let value = try DetachedES256Cose.protectedHeaders(
            kid: kid, contentType: contentType
        )
        let expected = Data([0xa3, 0x01, 0x26, 0x03, 0x78, UInt8(contentType.utf8.count)])
            + Data(contentType.utf8) + Data([0x04, 0x48]) + kid
        XCTAssertEqual(value, expected)
    }

    private func provisionChallenge(site: String, generation: UInt64) -> Data {
        var result = Data()
        result += field(1, Data("mnemosyne.thesaurophylax.site-root-bundle-receipt-provision.v1".utf8))
        result += field(2, Data(SiteRootConvergenceProfileV2.provisionPurpose.utf8))
        result += field(3, Data(site.utf8))
        result += field(4, Data("site-root-bundle-receipt-\(generation)".utf8))
        result += field(5, Data("site-root-device".utf8))
        result += field(6, Data([2]) + Data(repeating: 4, count: 32))
        result += field(7, Data(repeating: 5, count: 32))
        return result
    }

    private func pxra() -> Data {
        let issued = nowSeconds * 1_000 - 1_000
        var value = Data("PXRA/v2\u{1}".utf8)
        value += field(1, Data(repeating: 1, count: 16))
        value += field(2, Data(repeating: 2, count: 32))
        value += field(3, Data([1]))
        value += field(4, Data(repeating: 3, count: 16))
        value += field(5, u64(1))
        value += field(6, u64(2))
        value += field(7, Data(repeating: 4, count: 32))
        value += field(8, Data([1]))
        value += field(9, Data())
        value += field(10, u64(issued))
        value += field(11, u64(issued + 120_000))
        value += field(12, Data(repeating: 5, count: 32))
        value += field(13, u64(3))
        return value
    }

    private func x509Challenge(site: Data, transaction: Data, generation: UInt64) -> Data {
        var value = Data("PXFP/v1\u{1}".utf8)
        value += field(1, Data(SiteRootConvergenceProfileV2.x509Purpose.utf8))
        value += field(2, site)
        value += field(3, transaction)
        value += field(4, u64(generation))
        value += field(5, Data(SiteRootConvergenceProfileV2.x509RootPurpose.utf8))
        value += field(6, Data([2]) + Data(repeating: 6, count: 32))
        value += field(7, Data(repeating: 7, count: 32))
        value += field(8, Data(repeating: 8, count: 32))
        value += field(9, Data(SiteRootConvergenceProfileV2.x509IssuerPurpose.utf8))
        value += field(10, Data([3]) + Data(repeating: 9, count: 32))
        value += field(11, Data(repeating: 10, count: 32))
        value += field(12, Data(repeating: 11, count: 32))
        value += field(13, u64(nowSeconds + 120))
        value += field(14, Data(repeating: 12, count: 32))
        return value
    }

    private func field(_ tag: UInt8, _ value: Data) -> Data {
        Data([tag, UInt8(value.count >> 8), UInt8(truncatingIfNeeded: value.count)]) + value
    }

    private func u64(_ value: UInt64) -> Data {
        SiteRootConvergenceEncoding.uint64Bytes(value)
    }

    private func b64(_ value: Data) -> String { SiteRootConvergenceEncoding.encode(value) }

    private func json(_ object: [String: Any]) -> String {
        String(data: try! JSONSerialization.data(withJSONObject: object), encoding: .utf8)!
    }
}
