import Foundation
import Testing
@testable import PistisCore

private let keyID = Data(0 ..< 32)
private let lowSignature = Data([1] + Array(repeating: 0, count: 31)
    + Array(repeating: 0, count: 31) + [1])

private func coseFixture(_ name: String) throws -> Data {
    let fixtureURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("../../../../fixtures/protocol-v1/cose/\(name)")
        .standardizedFileURL
    let text = try String(contentsOf: fixtureURL, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard !text.isEmpty, text.count.isMultiple(of: 2) else {
        throw FixtureError.invalidHex
    }
    var result = Data()
    result.reserveCapacity(text.count / 2)
    var index = text.startIndex
    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index ..< next], radix: 16) else {
            throw FixtureError.invalidHex
        }
        result.append(byte)
        index = next
    }
    return result
}

private enum FixtureError: Error {
    case invalidHex
}

@Test func consumesSharedPositiveCoseFixtureExactly() throws {
    let envelopeBytes = try coseFixture("positive-envelope.hex")
    let envelope = try CoseSign1.decode(envelopeBytes)

    #expect(envelope.keyID == (try coseFixture("key-id.hex")))
    #expect(envelope.payload == (try coseFixture("payload.hex")))
    #expect(envelope.signature == (try coseFixture("signature.hex")))
    #expect(envelope.signatureStructure() == (try coseFixture("signing-input.hex")))
    #expect(envelope.encoded() == envelopeBytes)
}

@Test func rejectsSharedStructuralNegativeCoseFixtures() throws {
    let names = [
        "negative-tagged-envelope.hex",
        "negative-detached-payload.hex",
        "negative-unprotected-header.hex",
        "negative-unknown-protected-header.hex",
        "negative-wrong-algorithm.hex",
        "negative-high-s-signature.hex",
    ]
    for name in names {
        #expect(throws: CoseSign1Error.self, "accepted \(name)") {
            try CoseSign1.decode(coseFixture(name))
        }
    }
}

@Test func sharedPayloadSubstitutionChangesTheSignedBytes() throws {
    // Substitution remains structurally valid COSE. The independent ES256
    // verifier must reject it; this portable test proves it cannot retain the
    // accepted fixture's signing input.
    let substituted = try CoseSign1.decode(
        coseFixture("negative-substituted-payload.hex")
    )
    #expect(substituted.signatureStructure() != (try coseFixture("signing-input.hex")))
    #expect(substituted.signature == (try coseFixture("signature.hex")))
}

@Test func coseSign1RoundTripPreservesExactPayload() throws {
    let payload = Data([0xa2, 0x01, 0x01, 0x02, 0x43, 0, 1, 2])
    let envelope = try CoseSign1(
        keyID: keyID,
        payload: payload,
        signature: lowSignature
    )
    let decoded = try CoseSign1.decode(envelope.encoded())

    #expect(decoded == envelope)
    #expect(decoded.payload == payload)
    #expect(envelope.encoded().first == 0x84)
}

@Test func signatureStructureIsDeterministicAndBindsHeadersAndPayload() throws {
    let payload = Data([0xa0])
    let first = try CoseSign1.signatureStructure(keyID: keyID, payload: payload)
    let second = try CoseSign1.signatureStructure(keyID: keyID, payload: payload)

    #expect(first == second)
    #expect(first.first == 0x84)
    #expect(first.contains(Data("Signature1".utf8)))
    #expect(first.suffix(1) == payload)
}

@Test func rejectsTaggedAndUnprotectedRepresentations() throws {
    let valid = try CoseSign1(
        keyID: keyID,
        payload: Data([0xa0]),
        signature: lowSignature
    ).encoded()
    var tagged = Data([0xd2])
    tagged.append(valid)
    #expect(throws: CoseSign1Error.self) {
        try CoseSign1.decode(tagged)
    }

    var unprotected = valid
    // Array marker, uint8 byte-string marker and length, then 38 header bytes.
    let unprotectedIndex = 3 + 38
    unprotected[unprotectedIndex] = 0xa1
    #expect(throws: CoseSign1Error.self) {
        try CoseSign1.decode(unprotected)
    }
}

@Test func rejectsAlgorithmAndKeySubstitution() throws {
    let valid = try CoseSign1(
        keyID: keyID,
        payload: Data([0xa0]),
        signature: lowSignature
    ).encoded()
    var wrongAlgorithm = valid
    let algorithmIndex = 5
    wrongAlgorithm[algorithmIndex] = 0x27
    #expect(throws: CoseSign1Error.self) {
        try CoseSign1.decode(wrongAlgorithm)
    }

    var reorderedHeaders = valid
    let firstHeaderKey = 4
    reorderedHeaders[firstHeaderKey] = 0x04
    #expect(throws: CoseSign1Error.self) {
        try CoseSign1.decode(reorderedHeaders)
    }
}

@Test func rejectsTrailingTruncatedAndNonCanonicalLengths() throws {
    let valid = try CoseSign1(
        keyID: keyID,
        payload: Data([0xa0]),
        signature: lowSignature
    ).encoded()
    #expect(throws: CoseSign1Error.self) {
        try CoseSign1.decode(valid + Data([0]))
    }
    #expect(throws: CoseSign1Error.self) {
        try CoseSign1.decode(valid.dropLast())
    }

    // Replace the canonical one-byte payload length with an overlong uint8.
    let payloadMarker = 2 + 37 + 1
    var overlong = valid
    overlong.replaceSubrange(payloadMarker ... payloadMarker, with: [0x58, 0x01])
    #expect(throws: CoseSign1Error.self) {
        try CoseSign1.decode(overlong)
    }
}

@Test func rejectsMalformedOrMalleableSignatures() throws {
    #expect(throws: CoseSign1Error.invalidSignature) {
        try CoseSign1(keyID: keyID, payload: Data([0xa0]), signature: Data(repeating: 0, count: 64))
    }
    var highS = lowSignature
    highS.replaceSubrange(32 ..< 64, with: Data(repeating: 0xff, count: 32))
    #expect(throws: CoseSign1Error.invalidSignature) {
        try CoseSign1(keyID: keyID, payload: Data([0xa0]), signature: highS)
    }
    #expect(throws: CoseSign1Error.invalidSignature) {
        try CoseSign1(keyID: keyID, payload: Data([0xa0]), signature: Data(repeating: 1, count: 63))
    }
    var outOfRangeR = lowSignature
    outOfRangeR.replaceSubrange(0 ..< 32, with: Data(repeating: 0xff, count: 32))
    #expect(throws: CoseSign1Error.invalidSignature) {
        try CoseSign1(keyID: keyID, payload: Data([0xa0]), signature: outOfRangeR)
    }
}

@Test func enforcesKeyAndPayloadBounds() {
    #expect(throws: CoseSign1Error.invalidKeyID) {
        try CoseSign1(
            keyID: Data(repeating: 0, count: 31),
            payload: Data(),
            signature: lowSignature
        )
    }
    #expect(throws: CoseSign1Error.payloadTooLarge) {
        try CoseSign1(
            keyID: keyID,
            payload: Data(repeating: 0, count: CoseSign1.maximumPayloadLength + 1),
            signature: lowSignature
        )
    }
    #expect(throws: CoseSign1Error.invalidKeyID) {
        try CoseSign1.signatureStructure(keyID: Data(), payload: Data([0xa0]))
    }
}

@Test func rejectsPayloadOutsideCanonicalPistisCBORProfile() {
    let invalidPayloads = [
        Data(),
        Data([0xa2, 0x02, 0xf4, 0x01, 0xf5]), // out-of-order map keys
        Data([0xa2, 0x01, 0xf4, 0x01, 0xf5]), // duplicate map keys
        Data([0x18, 0x01]), // overlong integer
        Data([0xd8, 0x18, 0xa0]), // tag
        Data([0x9f, 0xff]), // indefinite array
        Data([0x61, 0xff]), // invalid UTF-8
        Data([0xa0, 0xa0]), // trailing value
    ]
    for payload in invalidPayloads {
        #expect(throws: CoseSign1Error.nonCanonical) {
            try CoseSign1(
                keyID: keyID,
                payload: payload,
                signature: lowSignature
            )
        }
    }
}

@Test func acceptsAllPermittedCanonicalValueClasses() throws {
    // {0: false, 1: null, 2: [-1, h'01', "x"]}
    let payload = Data([
        0xa3, 0x00, 0xf4, 0x01, 0xf6, 0x02, 0x83, 0x20, 0x41, 0x01, 0x61, 0x78,
    ])
    _ = try CoseSign1(
        keyID: keyID,
        payload: payload,
        signature: lowSignature
    )
}
