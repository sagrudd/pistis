import Crypto
import Foundation
import Testing
@testable import PistisCore

private let fixtureURL = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .appendingPathComponent(
        "../../../../fixtures/protocol-v3/first-device/presentation-positive.json"
    )
    .standardizedFileURL

private func fixture() throws -> [String: Any] {
    let data = try Data(contentsOf: fixtureURL)
    return try #require(
        JSONSerialization.jsonObject(with: data) as? [String: Any]
    )
}

@Test
func canonicalFirstDeviceBindingIsStable() throws {
    let document = try fixture()
    let presentation = try FirstDevicePresentationV3.verify(
        qrText: try #require(document["qr_text"] as? String),
        expectedAppConfigurationDigest: try appDigest(document),
        now: Date(timeIntervalSince1970: 1_700_000_060)
    )
    let publicKey = Data([
        0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
        0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
        0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
        0x96,
    ])
    let keyID = Data(SHA256.hash(
        data: Data("pistis:key-id:v1\0".utf8) + publicKey
    ))
    let binding = try EnrolmentBindingInput(
        operationID: Data(repeating: 0x10, count: 16),
        presentation: presentation,
        numericSubject: UInt64.max,
        devicePublicKey: publicKey,
        deviceKeyID: keyID,
        policyGeneration: 7,
        authorityChallenge: Data(repeating: 0x66, count: 32),
        authorityChallengeExpiresAtMilliseconds: 1_700_000_240_000
    )
    let digest = Data(SHA256.hash(data: EnrolmentBindingV1.payload(binding)))
    #expect(
        digest.map { String(format: "%02x", $0) }.joined()
            == "628961626fb2fa5d40665426915bb3487a9581671ef76da8874d73dd80f7bf38"
    )
}

private func hex(_ value: String) throws -> Data {
    guard value.count.isMultiple(of: 2) else {
        throw FirstDevicePresentationError.malformed
    }
    var output = Data()
    var index = value.startIndex
    while index < value.endIndex {
        let end = value.index(index, offsetBy: 2)
        guard let byte = UInt8(value[index ..< end], radix: 16) else {
            throw FirstDevicePresentationError.malformed
        }
        output.append(byte)
        index = end
    }
    return output
}

private func appDigest(_ document: [String: Any]) throws -> Data {
    try hex(try #require(document["app_configuration_digest_hex"] as? String))
}

@Test func verifiesSharedFirstDevicePresentationFixture() throws {
    let document = try fixture()
    let qr = try #require(document["qr_text"] as? String)
    let now = try #require(document["now_ms"] as? NSNumber).uint64Value
    let verified = try FirstDevicePresentationV3.verify(
        qrText: qr,
        expectedAppConfigurationDigest: try appDigest(document),
        now: Date(timeIntervalSince1970: Double(now) / 1_000)
    )
    #expect(verified.presentationID == Data(repeating: 0x33, count: 16))
    #expect(verified.installationID == Data(repeating: 0x22, count: 16))
    #expect(verified.installationName == "Mnemosyne evaluation")
    #expect(verified.audience == "prosopikon:pistis:enrolment")
    #expect(verified.httpsOrigin.absoluteString == "https://pistis.example.test:8443")
}

@Test func rejectsConfigurationExpiryCorruptionKindAndTruncation() throws {
    let document = try fixture()
    let qr = try #require(document["qr_text"] as? String)
    let digest = try appDigest(document)
    #expect(throws: FirstDevicePresentationError.wrongConfiguration) {
        try FirstDevicePresentationV3.verify(
            qrText: qr,
            expectedAppConfigurationDigest: Data(repeating: 0, count: 32),
            now: Date(timeIntervalSince1970: 1_700_000_060)
        )
    }
    #expect(throws: FirstDevicePresentationError.expired) {
        try FirstDevicePresentationV3.verify(
            qrText: qr,
            expectedAppConfigurationDigest: digest,
            now: Date(timeIntervalSince1970: 1_700_000_300)
        )
    }
    var frame = try hex(try #require(document["frame_hex"] as? String))
    frame[4] = 2
    let wrongKind = transfer(frame)
    #expect(throws: (any Error).self) {
        try FirstDevicePresentationV3.verify(
            qrText: wrongKind,
            expectedAppConfigurationDigest: digest,
            now: Date(timeIntervalSince1970: 1_700_000_060)
        )
    }
    for length in 0 ..< qr.count {
        let end = qr.index(qr.startIndex, offsetBy: length)
        #expect(throws: (any Error).self) {
            try FirstDevicePresentationV3.verify(
                qrText: String(qr[..<end]),
                expectedAppConfigurationDigest: digest,
                now: Date(timeIntervalSince1970: 1_700_000_060)
            )
        }
    }
}

private func transfer(_ frame: Data) -> String {
    let body = frame.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    let checksum = SHA256.hash(data: Data("PISTIS1:\(body)".utf8)).prefix(8)
        .map { String(format: "%02x", $0) }.joined()
    return "PISTIS1:\(body).\(checksum)"
}
