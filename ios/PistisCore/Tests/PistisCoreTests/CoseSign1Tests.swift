import Foundation
import Testing
@testable import PistisCore

private let keyID = Data(0 ..< 32)
private let lowSignature = Data([1] + Array(repeating: 0, count: 31)
    + Array(repeating: 0, count: 31) + [1])

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
        try CoseSign1(keyID: keyID, payload: Data(), signature: Data(repeating: 0, count: 64))
    }
    var highS = lowSignature
    highS.replaceSubrange(32 ..< 64, with: Data(repeating: 0xff, count: 32))
    #expect(throws: CoseSign1Error.invalidSignature) {
        try CoseSign1(keyID: keyID, payload: Data(), signature: highS)
    }
    #expect(throws: CoseSign1Error.invalidSignature) {
        try CoseSign1(keyID: keyID, payload: Data(), signature: Data(repeating: 1, count: 63))
    }
    var outOfRangeR = lowSignature
    outOfRangeR.replaceSubrange(0 ..< 32, with: Data(repeating: 0xff, count: 32))
    #expect(throws: CoseSign1Error.invalidSignature) {
        try CoseSign1(keyID: keyID, payload: Data(), signature: outOfRangeR)
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
        try CoseSign1.signatureStructure(keyID: Data(), payload: Data())
    }
}
