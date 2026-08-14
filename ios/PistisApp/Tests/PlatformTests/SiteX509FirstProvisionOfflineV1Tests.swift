import CryptoKit
import XCTest
@testable import Pistis

final class SiteX509FirstProvisionOfflineV1Tests: XCTestCase {
    func testStrictPresentationAndCanonicalResponseBindEveryCoordinate() throws {
        let bytes = try presentation()
        let qr = SiteX509FirstProvisionOfflineProfileV1.presentationQRPrefix
            + SiteX509FirstProvisionOfflinePresentationV1.base64URL(bytes)
        let parsed = try SiteX509FirstProvisionOfflinePresentationV1(
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
        let response = try SecureEnclaveSiteX509FirstProvisionOfflineProducerV1.response(
            parsed, approval: approval, assertion: assertion
        )
        let responseFields = try fields(
            response, magic: SiteX509FirstProvisionOfflineProfileV1.responseMagic, count: 10
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
            try SecureEnclaveSiteX509FirstProvisionOfflineProducerV1.responseQRText(response)
                .hasPrefix(SiteX509FirstProvisionOfflineProfileV1.responseQRPrefix)
        )
    }

    func testExpiryAlternateQRAndEveryProtectedSubstitutionDeny() throws {
        let bytes = try presentation()
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV1(
            fileBytes: bytes, nowUnixSeconds: 1_200
        ))
        let encoded = SiteX509FirstProvisionOfflinePresentationV1.base64URL(bytes)
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV1(
            qrText: SiteX509FirstProvisionOfflineProfileV1.presentationQRPrefix + encoded + "=",
            nowUnixSeconds: 1_001
        ))
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV1(
            qrText: "PXFP1:P:" + encoded,
            nowUnixSeconds: 1_001
        ))
        for value in [
            SiteX509FirstProvisionOfflineProfileV1.purpose,
            SiteX509FirstProvisionOfflineProfileV1.audience,
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
            XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV1(
                fileBytes: changed, nowUnixSeconds: 1_001
            ), "substitution unexpectedly accepted for \(value)")
        }
        var changedIP = bytes
        let encodedIP = Data([4, 192, 168, 0, 193])
        let ipRange = try XCTUnwrap(changedIP.range(of: encodedIP))
        changedIP[ipRange.upperBound - 1] = 194
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV1(
            fileBytes: changedIP, nowUnixSeconds: 1_001
        ))
    }

    func testChallengeRejectsInvalidOrIdenticalRoleKeys() throws {
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV1(
            fileBytes: presentation(invalidRootKey: true), nowUnixSeconds: 1_001
        ))
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV1(
            fileBytes: presentation(identicalRoleKeys: true), nowUnixSeconds: 1_001
        ))
        XCTAssertThrowsError(try SiteX509FirstProvisionOfflinePresentationV1(
            fileBytes: presentation(approvalMatchesRoot: true), nowUnixSeconds: 1_001
        ))
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
            magic: SiteX509FirstProvisionOfflineProfileV1.challengeMagic,
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
            magic: SiteX509FirstProvisionOfflineProfileV1.contextMagic,
            fields: [
                Data(SiteX509FirstProvisionOfflineProfileV1.purpose.utf8),
                Data(SiteX509FirstProvisionOfflineProfileV1.audience.utf8),
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
            magic: SiteX509FirstProvisionOfflineProfileV1.presentationMagic,
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
