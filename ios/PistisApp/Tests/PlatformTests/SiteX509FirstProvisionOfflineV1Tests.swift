import CryptoKit
import XCTest
@testable import Pistis

final class SiteX509FirstProvisionOfflineV2Tests: XCTestCase {
    func testExactThesaurophylaxV2FixtureHasSwiftTranscriptParity() throws {
        let presentationHex = "505846502f76320201019b505846502f763101010019736974652d783530392d66697273742d70726f766973696f6e0200100101010101010101010101010101010103001002020202020202020202020202020202040008000000000000000105001e736974652d783530392d726f6f742d66697273742d70726f766973696f6e06002102591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf07002004040404040404040404040404040404040404040404040404040404040404040800200505050505050505050505050505050505050505050505050505050505050505090020736974652d783530392d6973737565722d66697273742d70726f766973696f6e0a00210273103ec30b3ccf57daae08e93534aef144a35940cf6bbba12a0cf7cbd5d65a640b002007070707070707070707070707070707070707070707070707070707070707070c002008080808080808080808080808080808080808080808080808080808080808080d000800000000000004b00e002009090909090909090909090909090909090909090909090909090909090909090200202583d23c060cdcb778dfebfc01dcb3b8b96e9ff9e333742b730b36e345d87dbe030010020202020202020202020202020202020401f2505843542f763200010024736974652d783530392d66697273742d70726f766973696f6e2d6f66666c696e652d763202002b7069737469733a736974652d783530392d66697273742d70726f766973696f6e2d6f66666c696e653a7632030029736974652d30303030303030302d303030302d303030302d303030302d303030303030303030303031040016617574686f726974792d67656e65726174696f6e2d31050014637573746f64792d67656e65726174696f6e2d3106000800000000000000010700080000000000000001080008000000000000000109000e696e7374616c6c6174696f6e2d310a00086465766963652d310b00106170702d6174746573742d6b65792d310c002a433741364e51545359342e6f72672e6d6e656d6f73796e6562696f736369656e6365732e7069737469730d0012637573746f6d65722d6170706c69616e63650e00200f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f003a000219736572766963652d6461736f626a65637473746f72652d73330104c0a800c111736572766963652d6d6f6e61732d7765620104c0a800c11000203c2ecbee6f676d257d0c8ae592d15e7ce5ab6ab4d16378c778b0535b52c2e75b110021027135fa4fd93a09dce98bbf681b4bfcf50e7c0d6354e62afb0bff2a3429617865050020d4b72eeb238874d0929d7be53117cabbe7fc1c8024b774265c6a990047dde42d0600200a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0700200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b08000800000000000003e809000800000000000004b0"
        let bytes = Data(hex: presentationHex)
        let parsed = try SiteX509FirstProvisionOfflinePresentationV2(
            fileBytes: bytes, nowUnixSeconds: 1_001
        )
        XCTAssertEqual(parsed.targetKind, "customer-appliance")
        XCTAssertEqual(
            try parsed.appAttestClientDataHash(detachedApproval: Data(repeating: 12, count: 64)),
            Data(hex: "e541216b18e892c6ebdaf01fb0ff3061844ecbcb90be83ee72ee9b14720ea8a6")
        )
    }

    func testStrictPresentationAndCanonicalResponseBindEveryCoordinate() throws {
        let bytes = try presentation()
        let qr = SiteX509FirstProvisionOfflineProfileV2.presentationQRPrefix
            + SiteX509FirstProvisionOfflinePresentationV2.base64URL(bytes)
        let parsed = try SiteX509FirstProvisionOfflinePresentationV2(
            qrText: qr, nowUnixSeconds: 1_001
        )
        XCTAssertEqual(parsed.siteTrustDomain, "site-00000000-0000-0000-0000-000000000001")
        XCTAssertEqual(parsed.authorityGeneration, "authority-generation-1")
        XCTAssertEqual(parsed.custodyGeneration, "custody-generation-1")
        XCTAssertEqual(parsed.revocationGeneration, 1)
        XCTAssertEqual(parsed.targetKind, "customer-appliance")
        XCTAssertNotEqual(parsed.siteRootApprovalPublicKey, parsed.rootPublicKey)
        XCTAssertNotEqual(parsed.siteRootApprovalPublicKey, parsed.issuerPublicKey)
        XCTAssertEqual(
            parsed.siteRootApprovalKeyID,
            Data(SHA256.hash(data: parsed.siteRootApprovalPublicKey))
        )
        XCTAssertEqual(parsed.services.map(\.serviceID), [
            "service-dasobjectstore-s3", "service-monas-web",
        ])
        XCTAssertEqual(parsed.services[0].privateIPs, ["192.168.0.193"])

        let approval = Data(repeating: 12, count: 64)
        let assertion = Data(repeating: 13, count: 128)
        let response = try SecureEnclaveSiteX509FirstProvisionOfflineProducerV2.response(
            parsed, approval: approval, assertion: assertion
        )
        let responseFields = try fields(
            response, magic: SiteX509FirstProvisionOfflineProfileV2.responseMagic, count: 10
        )
        XCTAssertEqual(responseFields[0], parsed.presentationDigest)
        XCTAssertEqual(responseFields[1], parsed.contextDigest)
        XCTAssertEqual(responseFields[2], parsed.challengeDigest)
        XCTAssertEqual(responseFields[3], parsed.transactionUUID)
        XCTAssertEqual(responseFields[4], parsed.replayReference)
        XCTAssertEqual(responseFields[5], parsed.ceremonyChallenge)
        XCTAssertEqual(responseFields[6], Data(SHA256.hash(data: approval)))
        XCTAssertEqual(responseFields[7], approval)
        XCTAssertEqual(responseFields[8], assertion)
        XCTAssertEqual(
            responseFields[9], try parsed.appAttestClientDataHash(detachedApproval: approval)
        )
        XCTAssertTrue(
            try SecureEnclaveSiteX509FirstProvisionOfflineProducerV2.responseQRText(response)
                .hasPrefix(SiteX509FirstProvisionOfflineProfileV2.responseQRPrefix)
        )
    }

    func testExpiryAlternateQRAndEveryProtectedSubstitutionDeny() throws {
        let bytes = try presentation()
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV2(
            fileBytes: bytes, nowUnixSeconds: 1_200
        ))
        let encoded = SiteX509FirstProvisionOfflinePresentationV2.base64URL(bytes)
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV2(
            qrText: SiteX509FirstProvisionOfflineProfileV2.presentationQRPrefix + encoded + "=",
            nowUnixSeconds: 1_001
        ))
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV2(
            qrText: "PXFP1:P:" + encoded,
            nowUnixSeconds: 1_001
        ))
        for value in [
            SiteX509FirstProvisionOfflineProfileV2.purpose,
            SiteX509FirstProvisionOfflineProfileV2.audience,
            "site-00000000-0000-0000-0000-000000000001",
            "authority-generation-1", "custody-generation-1", "installation-1",
            "device-1", "app-attest-key-1",
            AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
            "customer-appliance", "service-dasobjectstore-s3",
        ] {
            var changed = bytes
            let needle = Data(value.utf8)
            let range = try XCTUnwrap(changed.range(of: needle))
            changed[range.lowerBound] ^= 1
            XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV2(
                fileBytes: changed, nowUnixSeconds: 1_001
            ), "substitution unexpectedly accepted for \(value)")
        }
        var changedIP = bytes
        let encodedIP = Data([4, 192, 168, 0, 193])
        let ipRange = try XCTUnwrap(changedIP.range(of: encodedIP))
        changedIP[ipRange.upperBound - 1] = 194
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV2(
            fileBytes: changedIP, nowUnixSeconds: 1_001
        ))
    }

    func testChallengeRejectsInvalidOrIdenticalRoleKeys() throws {
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV2(
            fileBytes: presentation(invalidRootKey: true), nowUnixSeconds: 1_001
        ))
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV2(
            fileBytes: presentation(identicalRoleKeys: true), nowUnixSeconds: 1_001
        ))
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV2(
            fileBytes: presentation(approvalMatchesRoot: true), nowUnixSeconds: 1_001
        ))
    }

    @MainActor
    func testCoordinatorUsesSameBoundedParserForRawFile() throws {
        let coordinator = SiteX509FirstProvisionOfflineCoordinator()
        coordinator.accept(fileBytes: try presentation(), nowUnixSeconds: 1_001)
        XCTAssertEqual(coordinator.phase, .review)
        XCTAssertNotNil(coordinator.presentedReview)

        coordinator.accept(
            fileBytes: Data(
                repeating: 0,
                count: SiteX509FirstProvisionOfflineProfileV2.maximumPresentationFileBytes + 1
            ),
            nowUnixSeconds: 1_001
        )
        XCTAssertEqual(coordinator.phase, .failed)
        XCTAssertNil(coordinator.presentedReview)
    }

    private func presentation(
        invalidRootKey: Bool = false,
        identicalRoleKeys: Bool = false,
        approvalMatchesRoot: Bool = false
    ) throws -> Data {
        let root = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32))
        let issuer = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 4, count: 32))
        let approval = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 9, count: 32))
        let rootKey = invalidRootKey
            ? Data([2]) + Data(repeating: 0xff, count: 32)
            : compress(root.publicKey.x963Representation)
        let issuerKey = identicalRoleKeys
            ? rootKey
            : compress(issuer.publicKey.x963Representation)
        let approvalKey = approvalMatchesRoot
            ? rootKey
            : compress(approval.publicKey.x963Representation)
        let challenge = tlv(
            magic: SiteX509FirstProvisionOfflineProfileV2.challengeMagic,
            fields: [
                Data("site-x509-first-provision".utf8), Data(repeating: 1, count: 16),
                Data(repeating: 2, count: 16), u64(1),
                Data("site-x509-root-first-provision".utf8), rootKey,
                Data(repeating: 4, count: 32), Data(repeating: 5, count: 32),
                Data("site-x509-issuer-first-provision".utf8), issuerKey,
                Data(repeating: 7, count: 32), Data(repeating: 8, count: 32),
                u64(1_200), Data(repeating: 9, count: 32),
            ]
        )
        let services = serviceProjection([
            ("service-dasobjectstore-s3", [192, 168, 0, 193]),
            ("service-monas-web", [192, 168, 0, 193]),
        ])
        let context = tlv(
            magic: SiteX509FirstProvisionOfflineProfileV2.contextMagic,
            fields: [
                Data(SiteX509FirstProvisionOfflineProfileV2.purpose.utf8),
                Data(SiteX509FirstProvisionOfflineProfileV2.audience.utf8),
                Data("site-00000000-0000-0000-0000-000000000001".utf8),
                Data("authority-generation-1".utf8), Data("custody-generation-1".utf8),
                u64(1), u64(1), u64(1), Data("installation-1".utf8),
                Data("device-1".utf8), Data("app-attest-key-1".utf8),
                Data(AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier.utf8),
                Data("customer-appliance".utf8), Data(repeating: 15, count: 32), services,
                Data(SHA256.hash(data: approvalKey)), approvalKey,
            ]
        )
        return tlv(
            magic: SiteX509FirstProvisionOfflineProfileV2.presentationMagic,
            fields: [challenge, Data(SHA256.hash(data: challenge)), Data(repeating: 2, count: 16),
                     context, Data(SHA256.hash(data: context)), Data(repeating: 10, count: 32),
                     Data(repeating: 11, count: 32), u64(1_000), u64(1_200)]
        )
    }

    private func tlv(magic: Data, fields: [Data]) -> Data {
        var result = magic
        for (index, field) in fields.enumerated() {
            result.append(UInt8(index + 1)); result.append(UInt8(field.count >> 8))
            result.append(UInt8(field.count & 0xff)); result.append(field)
        }
        return result
    }
    private func fields(_ bytes: Data, magic: Data, count: Int) throws -> [Data] {
        XCTAssertTrue(bytes.starts(with: magic)); var cursor = magic.count; var result: [Data] = []
        for tag in 1 ... count {
            XCTAssertEqual(bytes[cursor], UInt8(tag))
            let length = Int(bytes[cursor + 1]) << 8 | Int(bytes[cursor + 2]); cursor += 3
            result.append(Data(bytes[cursor ..< cursor + length])); cursor += length
        }
        XCTAssertEqual(cursor, bytes.count); return result
    }
    private func u64(_ value: UInt64) -> Data {
        Data((0 ..< 8).reversed().map { UInt8(truncatingIfNeeded: value >> UInt64($0 * 8)) })
    }
    private func compress(_ x963: Data) -> Data {
        var result = Data([x963[64].isMultiple(of: 2) ? 2 : 3]); result.append(x963[1 ... 32])
        return result
    }
    private func serviceProjection(_ values: [(String, [UInt8])]) -> Data {
        var result = Data([0, UInt8(values.count)])
        for (id, ip) in values {
            result.append(UInt8(id.utf8.count)); result.append(Data(id.utf8))
            result.append(1); result.append(4); result.append(contentsOf: ip)
        }
        return result
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
