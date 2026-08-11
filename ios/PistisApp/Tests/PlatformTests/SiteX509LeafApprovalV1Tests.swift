import Foundation
import XCTest

@testable import Pistis

final class SiteX509LeafApprovalV1Tests: XCTestCase {
    func testExactPXLAAndCurrentAckGenerationAreAccepted() throws {
        let fixture = LeafFixture()
        let value = try fixture.decode()
        XCTAssertEqual(value.deviceKeyGeneration, 2)
        XCTAssertEqual(value.transactionID, fixture.transaction)
        XCTAssertNoThrow(try value.validateCurrentSigner(SiteRootConvergenceAckRecordV2(
            siteUUID: "00112233-4455-6677-8899-aabbccddeeff",
            targetIDB64URL: "public",
            ackPublicKeyB64URL: "public",
            generation: 2
        )))
        XCTAssertThrowsError(try value.validateCurrentSigner(SiteRootConvergenceAckRecordV2(
            siteUUID: "00112233-4455-6677-8899-aabbccddeeff",
            targetIDB64URL: "public", ackPublicKeyB64URL: "public", generation: 3
        )))
    }

    func testURLSafeUnpaddedAndUnknownJSONAreDenied() throws {
        var fixture = LeafFixture()
        fixture.object["correlation_id_b64"] = "_____________________w"
        XCTAssertThrowsError(try fixture.decode())

        fixture = LeafFixture()
        fixture.object["fallback"] = true
        XCTAssertThrowsError(try fixture.decode())
    }

    func testServiceOrderTagOrderAndTransactionBindingAreDeniedOnDrift() throws {
        var swapped = LeafFixture()
        swapped.payloadFields[8] = Data("service-monas-web".utf8)
        swapped.refreshPayload()
        XCTAssertThrowsError(try swapped.decode())

        var transaction = LeafFixture()
        transaction.object["transaction_id_b64"] = Data(repeating: 7, count: 16).base64EncodedString()
        XCTAssertThrowsError(try transaction.decode())

        var tag = LeafFixture()
        tag.payloadTags[4] = 6
        tag.refreshPayload()
        XCTAssertThrowsError(try tag.decode())
    }

    func testAcceptedEchoIsExactAndMinimal() throws {
        let presentation = try LeafFixture().decode()
        var accepted: [String: Any] = [
            "schema": SiteX509LeafApprovalProfileV1.acceptedSchema,
            "correlation_id_b64": presentation.correlationID.base64EncodedString(),
            "transaction_id_b64": presentation.transactionID.base64EncodedString(),
            "status": "accepted",
        ]
        XCTAssertNoThrow(try SiteX509LeafApprovalAcceptedV1(
            data: JSONSerialization.data(withJSONObject: accepted), expected: presentation
        ))
        accepted["credential"] = "forbidden"
        XCTAssertThrowsError(try SiteX509LeafApprovalAcceptedV1(
            data: JSONSerialization.data(withJSONObject: accepted), expected: presentation
        ))
    }
}

private struct LeafFixture {
    var object: [String: Any]
    var payloadTags = Array(UInt8(1) ... UInt8(26))
    var payloadFields: [Data]
    let transaction = Data(repeating: 2, count: 16)

    init() {
        let u64: (UInt64) -> Data = { withUnsafeBytes(of: $0.bigEndian) { Data($0) } }
        let digest = Data(repeating: 3, count: 32)
        payloadFields = [
            Data(hex: "00112233445566778899aabbccddeeff"),
            Data("x509-root-generation-1".utf8),
            Data("x509-issuing-generation-1".utf8),
            transaction,
            u64(900), u64(1_100), Data(repeating: 4, count: 32), u64(2),
            Data("service-dasobjectstore-s3".utf8),
            digest, digest, digest, Data(repeating: 5, count: 16), u64(900), u64(86_400), digest,
            Data("service-monas-web".utf8),
            digest, digest, digest, Data(repeating: 6, count: 16), u64(900), u64(86_400), digest,
            digest, digest,
        ]
        object = [:]
        refreshPayload()
    }

    mutating func refreshPayload() {
        var payload = Data("PXLA/v1".utf8) + Data([1])
        for (tag, field) in zip(payloadTags, payloadFields) {
            payload.append(tag)
            payload.append(contentsOf: UInt16(field.count).bigEndianBytes)
            payload.append(field)
        }
        object = [
            "schema": SiteX509LeafApprovalProfileV1.presentationSchema,
            "correlation_id_b64": Data(repeating: 1, count: 16).base64EncodedString(),
            "canonical_payload_b64": payload.base64EncodedString(),
            "transaction_id_b64": transaction.base64EncodedString(),
            "device_key_generation": 2,
            "delegation_serial": "delegation-1",
            "delegation_expires_at": 1_200,
            "purpose": SiteX509LeafApprovalProfileV1.purpose,
        ]
    }

    func decode() throws -> SiteX509LeafApprovalPresentationV1 {
        try SiteX509LeafApprovalPresentationV1(
            data: JSONSerialization.data(withJSONObject: object), nowUnixSeconds: 1_000
        )
    }
}

private extension Data {
    init(hex: String) {
        self.init()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            append(UInt8(hex[index ..< next], radix: 16)!)
            index = next
        }
    }
}

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] { withUnsafeBytes(of: bigEndian, Array.init) }
}
