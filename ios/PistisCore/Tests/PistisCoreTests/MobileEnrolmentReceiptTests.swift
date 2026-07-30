import Crypto
import Foundation
import Testing
@testable import PistisCore

@Test
func receiptRequiresPurposeSeparatedKeyAndExactDeviceBinding() throws {
    let presentation = try receiptPresentation()
    let deviceKey = try fixtureKey(1)
    let receiptKey = try fixtureKey(2)
    let installationKey = try fixtureKey(3)
    let devicePublic = deviceKey.publicKey.compressedRepresentation
    let deviceKeyID = keyID(devicePublic)
    let binding = try EnrolmentBindingInput(
        operationID: Data(repeating: 0x10, count: 16),
        presentation: presentation,
        numericSubject: 123_456_789,
        devicePublicKey: devicePublic,
        deviceKeyID: deviceKeyID,
        policyGeneration: 7,
        authorityChallenge: Data(repeating: 0x66, count: 32),
        authorityChallengeExpiresAtMilliseconds: 1_700_000_240_000
    )
    let registration = try signed(
        EnrolmentBindingV1.payload(binding),
        keyID: deviceKeyID,
        key: deviceKey
    )
    let validReceiptPayload = receiptPayload(
        presentation: presentation,
        installationPublicKey:
            installationKey.publicKey.compressedRepresentation,
        devicePublicKey: devicePublic,
        deviceKeyID: deviceKeyID,
        authorityKeyID:
            keyID(receiptKey.publicKey.compressedRepresentation),
        registration: registration
    )
    let receipt = try signed(
        validReceiptPayload,
        keyID: keyID(receiptKey.publicKey.compressedRepresentation),
        key: receiptKey
    )
    let verified = try MobileEnrolmentReceiptV2.verify(
        returnedAuthorityBundle: presentation.authorityBundle,
        returnedRegistrationCOSE: registration,
        receiptCOSE: receipt,
        expectedRegistrationCOSE: registration,
        binding: binding,
        now: Date(timeIntervalSince1970: 1_700_000_100)
    )
    #expect(verified.installationID == presentation.installationID)
    #expect(verified.deviceKeyID == deviceKeyID)
    #expect(verified.allowedHTTPSHosts == ["pistis.example.test"])
    #expect(
        verified.authorisedProductAudiences
            == ["dasobjectstore", "jenkins", "propylaion"]
    )

    let wrongPurposeReceipt = try signed(
        validReceiptPayload,
        keyID: keyID(deviceKey.publicKey.compressedRepresentation),
        key: deviceKey
    )
    #expect(throws: (any Error).self) {
        try MobileEnrolmentReceiptV2.verify(
            returnedAuthorityBundle: presentation.authorityBundle,
            returnedRegistrationCOSE: registration,
            receiptCOSE: wrongPurposeReceipt,
            expectedRegistrationCOSE: registration,
            binding: binding,
            now: Date(timeIntervalSince1970: 1_700_000_100)
        )
    }

    var changedRegistration = registration
    changedRegistration[changedRegistration.count - 1] ^= 1
    #expect(throws: (any Error).self) {
        try MobileEnrolmentReceiptV2.verify(
            returnedAuthorityBundle: presentation.authorityBundle,
            returnedRegistrationCOSE: changedRegistration,
            receiptCOSE: receipt,
            expectedRegistrationCOSE: changedRegistration,
            binding: binding,
            now: Date(timeIntervalSince1970: 1_700_000_100)
        )
    }

    for invalidPayload in [
        receiptPayload(
            presentation: presentation,
            installationPublicKey:
                installationKey.publicKey.compressedRepresentation,
            devicePublicKey: devicePublic,
            deviceKeyID: deviceKeyID,
            authorityKeyID:
                keyID(receiptKey.publicKey.compressedRepresentation),
            registration: registration,
            externalIdentityID: Data(repeating: 0, count: 16)
        ),
        receiptPayload(
            presentation: presentation,
            installationPublicKey:
                installationKey.publicKey.compressedRepresentation,
            devicePublicKey: devicePublic,
            deviceKeyID: deviceKeyID,
            authorityKeyID:
                keyID(receiptKey.publicKey.compressedRepresentation),
            registration: registration,
            deviceID: Data(repeating: 0, count: 16)
        ),
        receiptPayload(
            presentation: presentation,
            installationPublicKey:
                installationKey.publicKey.compressedRepresentation,
            devicePublicKey: devicePublic,
            deviceKeyID: deviceKeyID,
            authorityKeyID:
                keyID(receiptKey.publicKey.compressedRepresentation),
            registration: registration,
            policyGeneration: 0,
            revocationGeneration: 0
        ),
        receiptPayload(
            presentation: presentation,
            installationPublicKey:
                Data([0x04]) + Data(repeating: 0xff, count: 32),
            devicePublicKey: devicePublic,
            deviceKeyID: deviceKeyID,
            authorityKeyID:
                keyID(receiptKey.publicKey.compressedRepresentation),
            registration: registration
        ),
        receiptPayload(
            presentation: presentation,
            installationPublicKey:
                installationKey.publicKey.compressedRepresentation,
            devicePublicKey: devicePublic,
            deviceKeyID: deviceKeyID,
            authorityKeyID:
                keyID(receiptKey.publicKey.compressedRepresentation),
            registration: registration,
            confirmedAtMilliseconds: 1_700_000_200_000
        ),
    ] {
        let invalidReceipt = try signed(
            invalidPayload,
            keyID: keyID(receiptKey.publicKey.compressedRepresentation),
            key: receiptKey
        )
        #expect(throws: (any Error).self) {
            try MobileEnrolmentReceiptV2.verify(
                returnedAuthorityBundle: presentation.authorityBundle,
                returnedRegistrationCOSE: registration,
                receiptCOSE: invalidReceipt,
                expectedRegistrationCOSE: registration,
                binding: binding,
                now: Date(timeIntervalSince1970: 1_700_000_100)
            )
        }
    }
}

private func receiptPayload(
    presentation: VerifiedFirstDevicePresentation,
    installationPublicKey: Data,
    devicePublicKey: Data,
    deviceKeyID: Data,
    authorityKeyID: Data,
    registration: Data,
    externalIdentityID: Data = Data(repeating: 0x72, count: 16),
    deviceID: Data = Data(repeating: 0x73, count: 16),
    policyGeneration: UInt64 = 7,
    revocationGeneration: UInt64 = 1,
    confirmedAtMilliseconds: UInt64 = 1_700_000_090_000
) -> Data {
    var result = Data([0xb8, 0x1b])
    func field(_ key: UInt64, _ value: Data) {
        result.append(ReceiptCBOR.unsigned(key)); result.append(value)
    }
    field(0, ReceiptCBOR.unsigned(2))
    field(1, ReceiptCBOR.text("pistis.mobile-enrolment-receipt.v2"))
    field(2, ReceiptCBOR.unsigned(1_700_000_090_000))
    field(3, ReceiptCBOR.unsigned(1_700_000_290_000))
    field(4, ReceiptCBOR.bytes(Data(repeating: 0x71, count: 16)))
    field(5, ReceiptCBOR.bytes(presentation.installationID))
    field(6, ReceiptCBOR.text(presentation.installationName))
    field(7, ReceiptCBOR.text(presentation.audience))
    field(8, ReceiptCBOR.bytes(keyID(installationPublicKey)))
    field(9, ReceiptCBOR.bytes(installationPublicKey))
    field(10, Data([0x26]))
    field(11, ReceiptCBOR.bytes(Data(SHA256.hash(data: installationPublicKey))))
    field(12, ReceiptCBOR.bytes(authorityKeyID))
    field(13, ReceiptCBOR.bytes(presentation.principalID))
    field(14, ReceiptCBOR.bytes(externalIdentityID))
    field(15, ReceiptCBOR.bytes(deviceID))
    field(16, ReceiptCBOR.bytes(deviceKeyID))
    field(17, ReceiptCBOR.bytes(devicePublicKey))
    field(18, Data([0x26]))
    field(19, ReceiptCBOR.text("secure-enclave-biometry-current-set"))
    field(20, ReceiptCBOR.bytes(Data(SHA256.hash(data: registration))))
    field(21, ReceiptCBOR.unsigned(policyGeneration))
    field(22, ReceiptCBOR.unsigned(revocationGeneration))
    field(23, Data([0xf5]))
    field(24, ReceiptCBOR.unsigned(confirmedAtMilliseconds))
    field(25, Data([0x81]) + ReceiptCBOR.text("pistis.example.test"))
    field(
        26,
        Data([0x83])
            + ReceiptCBOR.text("dasobjectstore")
            + ReceiptCBOR.text("jenkins")
            + ReceiptCBOR.text("propylaion")
    )
    return result
}

private func fixtureKey(_ scalar: UInt8) throws -> P256.Signing.PrivateKey {
    try P256.Signing.PrivateKey(
        rawRepresentation: Data(repeating: 0, count: 31) + Data([scalar])
    )
}

private func keyID(_ publicKey: Data) -> Data {
    Data(SHA256.hash(
        data: Data("pistis:key-id:v1\0".utf8) + publicKey
    ))
}

private func signed(
    _ payload: Data,
    keyID: Data,
    key: P256.Signing.PrivateKey
) throws -> Data {
    let structure = try CoseSign1.signatureStructure(
        keyID: keyID,
        payload: payload
    )
    var signature = try key.signature(for: structure).rawRepresentation
    signature.replaceSubrange(
        32 ..< 64,
        with: lowS(Data(signature.suffix(32)))
    )
    return try CoseSign1(
        keyID: keyID,
        payload: payload,
        signature: signature
    ).encoded()
}

private func lowS(_ scalar: Data) -> Data {
    let halfOrder = Data([
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
        0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
    ])
    guard halfOrder.lexicographicallyPrecedes(scalar) else { return scalar }
    let order = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ]
    let source = [UInt8](scalar)
    var result = [UInt8](repeating: 0, count: 32)
    var borrow = 0
    for index in stride(from: 31, through: 0, by: -1) {
        var difference = order[index] - Int(source[index]) - borrow
        if difference < 0 { difference += 256; borrow = 1 } else { borrow = 0 }
        result[index] = UInt8(difference)
    }
    return Data(result)
}

private func receiptPresentation() throws -> VerifiedFirstDevicePresentation {
    let url = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent(
            "../../../../fixtures/protocol-v4/first-device/presentation-positive.json"
        )
        .standardizedFileURL
    let object = try #require(
        JSONSerialization.jsonObject(with: Data(contentsOf: url))
            as? [String: Any]
    )
    return try FirstDevicePresentationV4.verify(
        qrText: try #require(object["qr_text"] as? String),
        expectedAppConfigurationDigest: try receiptHex(
            try #require(object["app_configuration_digest_hex"] as? String)
        ),
        now: Date(timeIntervalSince1970: 1_700_000_060)
    )
}

private func receiptHex(_ value: String) throws -> Data {
    var result = Data()
    var index = value.startIndex
    while index < value.endIndex {
        let end = value.index(index, offsetBy: 2)
        result.append(try #require(UInt8(value[index ..< end], radix: 16)))
        index = end
    }
    return result
}

private enum ReceiptCBOR {
    static func unsigned(_ value: UInt64) -> Data {
        argument(major: 0, value: value)
    }
    static func bytes(_ value: Data) -> Data {
        argument(major: 2, value: UInt64(value.count)) + value
    }
    static func text(_ value: String) -> Data {
        let bytes = Data(value.utf8)
        return argument(major: 3, value: UInt64(bytes.count)) + bytes
    }
    private static func argument(major: UInt8, value: UInt64) -> Data {
        if value < 24 { return Data([major << 5 | UInt8(value)]) }
        if value <= UInt8.max { return Data([major << 5 | 24, UInt8(value)]) }
        if value <= UInt16.max {
            let number = UInt16(value).bigEndian
            return Data([major << 5 | 25])
                + withUnsafeBytes(of: number) { Data($0) }
        }
        if value <= UInt32.max {
            let number = UInt32(value).bigEndian
            return Data([major << 5 | 26])
                + withUnsafeBytes(of: number) { Data($0) }
        }
        let number = value.bigEndian
        return Data([major << 5 | 27])
            + withUnsafeBytes(of: number) { Data($0) }
    }
}
