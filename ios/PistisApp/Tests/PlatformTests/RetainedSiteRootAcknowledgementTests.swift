import CryptoKit
import Foundation
import XCTest
@testable import Pistis

final class RetainedSiteRootAcknowledgementTests: XCTestCase {
    // Synthetic bytes emitted by Proxenos' actual public PXRA/v2 encoder.
    private let vector = "505852412f7632010100100101010101010101010101010101010102002002020202020202020202020202020202020202020202020202020202020202020300010104001003030303030303030303030303030303050008000000000000000106000800000000000000010700200404040404040404040404040404040404040404040404040404040404040404080001010900000a0008000001ba60d338000b0008000001ba60d7cbe00c002005050505050505050505050505050505050505050505050505050505050505050d00080000000000000001"
    private let now: UInt64 = 1_900_000_000_001

    private func presentation() throws -> SiteRootConvergenceAckPresentationV2 {
        let chars = Array(vector)
        let bytes = Data(stride(from: 0, to: chars.count, by: 2).map {
            UInt8(String(chars[$0...($0 + 1)]), radix: 16)!
        })
        let origin = URL(string: "https://nuc.example.test")!
        let object = [
            "schema": SiteRootConvergenceProfileV2.ackSchema,
            "purpose": SiteRootConvergenceProfileV2.ackPurpose,
            "unsigned_pxra_v2_b64url": SiteRootConvergenceEncoding.encode(bytes),
            "submission_url": origin.absoluteString + SiteRootConvergenceProfileV2.ackSubmissionPath,
        ]
        return try SiteRootConvergenceAckPresentationV2(
            qrText: String(decoding: JSONSerialization.data(withJSONObject: object), as: UTF8.self),
            authorityOrigin: origin, nowUnixMilliseconds: now
        )
    }

    func testActualNativeTargetDiffersFromPhoneSignerAndOriginalBytesAreSigned() async throws {
        let value = try presentation()
        let site = P256.Signing.PrivateKey()
        let ack = P256.Signing.PrivateKey()
        let phone = Data(SHA256.hash(data: site.publicKey.compressedRepresentation))
        XCTAssertNotEqual(value.assertion.targetID, phone)
        let record = SiteRootConvergenceAckRecordV2(
            siteUUID: value.assertion.siteUUIDText,
            targetIDB64URL: SiteRootConvergenceEncoding.encode(phone),
            ackPublicKeyB64URL: SiteRootConvergenceEncoding.encode(ack.publicKey.compressedRepresentation),
            generation: 1
        )
        var signs = 0
        var sends = 0
        try await RetainedSiteRootAcknowledgementV2.submit(
            value, record: record, siteRootPublic: site.publicKey.compressedRepresentation,
            ackPublic: ack.publicKey.compressedRepresentation, nowMilliseconds: now,
            sign: { message in
                signs += 1
                return try P256Format.rawSignature(fromStrictDER: ack.signature(for: message).derRepresentation)
            },
            send: { data, endpoint in
                sends += 1
                XCTAssertEqual(data.prefix(value.unsignedPXRA.count), value.unsignedPXRA)
                XCTAssertEqual(endpoint, value.submissionURL)
                let signature = try P256.Signing.ECDSASignature(rawRepresentation: data.suffix(64))
                let headers = try DetachedES256Cose.protectedHeaders(
                    kid: SiteRootConvergenceEncoding.uint64Bytes(1),
                    contentType: SiteRootConvergenceProfileV2.pxraContentType
                )
                let message = try DetachedES256Cose.signatureStructure(protected: headers, payload: value.unsignedPXRA)
                XCTAssertTrue(ack.publicKey.isValidSignature(signature, for: message))
            }
        )
        XCTAssertEqual(signs, 1)
        XCTAssertEqual(sends, 1)
    }

    func testWrongRetainedBindingsAndExpiredPresentationDenyBeforeSigning() async throws {
        let value = try presentation()
        let site = P256.Signing.PrivateKey().publicKey.compressedRepresentation
        let ack = P256.Signing.PrivateKey().publicKey.compressedRepresentation
        let phone = SiteRootConvergenceEncoding.encode(Data(SHA256.hash(data: site)))
        let ackText = SiteRootConvergenceEncoding.encode(ack)
        let siteText = value.assertion.siteUUIDText
        let records: [SiteRootConvergenceAckRecordV2?] = [
            nil,
            SiteRootConvergenceAckRecordV2(siteUUID: "other", targetIDB64URL: phone, ackPublicKeyB64URL: ackText, generation: 1),
            SiteRootConvergenceAckRecordV2(siteUUID: siteText, targetIDB64URL: "malformed", ackPublicKeyB64URL: ackText, generation: 1),
            SiteRootConvergenceAckRecordV2(siteUUID: siteText, targetIDB64URL: phone, ackPublicKeyB64URL: "malformed", generation: 1),
            SiteRootConvergenceAckRecordV2(siteUUID: siteText, targetIDB64URL: phone, ackPublicKeyB64URL: ackText, generation: 0),
            SiteRootConvergenceAckRecordV2(siteUUID: siteText, targetIDB64URL: phone, ackPublicKeyB64URL: ackText, generation: 2),
        ]
        for record in records {
            do {
                try await RetainedSiteRootAcknowledgementV2.submit(
                    value, record: record, siteRootPublic: site, ackPublic: ack,
                    nowMilliseconds: now,
                    sign: { _ in XCTFail("Invalid binding reached signing"); return Data() },
                    send: { _, _ in XCTFail("Invalid binding reached submission") }
                )
                XCTFail("Invalid retained record accepted")
            } catch { }
        }
        let valid = SiteRootConvergenceAckRecordV2(siteUUID: siteText, targetIDB64URL: phone, ackPublicKeyB64URL: ackText, generation: 1)
        for keys in [(Data(), ack), (site, Data()), (Data(repeating: 0, count: 33), ack)] {
            do {
                try await RetainedSiteRootAcknowledgementV2.submit(
                    value, record: valid, siteRootPublic: keys.0, ackPublic: keys.1,
                    nowMilliseconds: now,
                    sign: { _ in XCTFail("Missing key reached signing"); return Data() },
                    send: { _, _ in XCTFail("Missing key reached submission") }
                )
                XCTFail("Missing or malformed key accepted")
            } catch { }
        }
        do {
            try await RetainedSiteRootAcknowledgementV2.submit(
                value, record: valid, siteRootPublic: site, ackPublic: ack,
                nowMilliseconds: value.assertion.expiresAtUnixMilliseconds,
                sign: { _ in XCTFail("Expired presentation reached signing"); return Data() },
                send: { _, _ in XCTFail("Expired presentation reached submission") }
            )
            XCTFail("Expired presentation accepted")
        } catch { }
    }

    func testProductionRouteUsesOnlyExistingRegistrationAndKeys() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/Platform/SiteRootConvergenceService.swift")
        let text = try String(contentsOf: source, encoding: .utf8)
        let start = try XCTUnwrap(text.range(of: "    func acknowledge(_ presentation:"))
        let end = try XCTUnwrap(text.range(of: "    private static func siteRootDeviceKeyID", range: start.upperBound..<text.endIndex))
        let route = String(text[start.lowerBound..<end.lowerBound])
        XCTAssertTrue(route.contains("try store.current()"))
        XCTAssertTrue(route.contains("try siteRoot.hasExistingKey(), try ack.hasExistingKey()"))
        XCTAssertTrue(route.contains("FaceIDCeremonyContext.authenticate"))
        for forbidden in [".create(", "registerAckKey(", "store.retain("] {
            XCTAssertFalse(route.contains(forbidden))
        }
    }
}
