import CryptoKit
import Foundation
import Testing
@testable import PistisCore

/// Swift conformance parser for the accepted ADR 0021 review vectors.
///
/// This is deliberately not part of PistisCore's product target. Moving this
/// behavior into production requires ADR acceptance and specialist review.
private enum ProposedQRV2ReviewParser {
    enum Kind: UInt8 {
        case challenge = 1
        case response = 2
    }

    enum Failure: Error {
        case invalid
    }

    static func parse(_ text: String, expectedKind: Kind) throws -> CoseSign1 {
        guard text.utf8.count <= 2_331,
              text.unicodeScalars.allSatisfy(\.isASCII),
              text.hasPrefix("PISTIS1:"),
              let separator = text.lastIndex(of: ".")
        else {
            throw Failure.invalid
        }
        let bodyStart = text.index(text.startIndex, offsetBy: 8)
        let body = String(text[bodyStart ..< separator])
        let checksum = String(text[text.index(after: separator)...])
        guard !body.isEmpty,
              checksum.count == 16,
              checksum.allSatisfy({ $0.isNumber || ("a" ... "f").contains($0) }),
              !body.contains("="),
              body.allSatisfy({
                  $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_")
              })
        else {
            throw Failure.invalid
        }

        let checked = Data("PISTIS1:\(body)".utf8)
        let expectedChecksum = SHA256.hash(data: checked)
            .prefix(8)
            .map { String(format: "%02x", $0) }
            .joined()
        guard checksum == expectedChecksum,
              let frame = decodeBase64URL(body),
              frame.count >= 10,
              frame[0] == 0xa3,
              frame[1] == 0x00,
              frame[2] == 0x02,
              frame[3] == 0x01,
              frame[4] == expectedKind.rawValue,
              frame[5] == 0x02,
              frame[6] == 0x59
        else {
            throw Failure.invalid
        }
        let envelopeLength = Int(frame[7]) << 8 | Int(frame[8])
        guard envelopeLength == frame.count - 9 else {
            throw Failure.invalid
        }
        return try CoseSign1.decode(frame.dropFirst(9))
    }

    private static func decodeBase64URL(_ text: String) -> Data? {
        var base64 = text.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64.append(String(repeating: "=", count: (4 - base64.count % 4) % 4))
        return Data(base64Encoded: base64)
    }
}

/// Conformance shape of the enrolled trust lookup required by accepted ADR 0021.
private protocol ProposedInstallationKeyLookup {
    func compressedPublicKey(for keyID: Data) -> Data?
}

private struct ProposedReviewKeyLookup: ProposedInstallationKeyLookup {
    let keyID: Data
    let compressedPublicKey: Data

    func compressedPublicKey(for keyID: Data) -> Data? {
        keyID == self.keyID ? compressedPublicKey : nil
    }
}

private func verifyWithEnrolledKey(
    _ envelope: CoseSign1,
    lookup: any ProposedInstallationKeyLookup
) throws {
    guard let encodedKey = lookup.compressedPublicKey(for: envelope.keyID) else {
        throw ProposedQRV2ReviewParser.Failure.invalid
    }
    let publicKey = try P256.Signing.PublicKey(compressedRepresentation: encodedKey)
    let signature = try P256.Signing.ECDSASignature(rawRepresentation: envelope.signature)
    guard publicKey.isValidSignature(signature, for: envelope.signatureStructure()) else {
        throw ProposedQRV2ReviewParser.Failure.invalid
    }
}

private func proposedResponseTransfer() throws -> String {
    let fixtureURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("../../../../fixtures/proposed-qr-v2/response-positive.qr.txt")
        .standardizedFileURL
    return try String(contentsOf: fixtureURL, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
}

@Test func proposedV2ResponseVectorContainsTheAcceptedCoseFixture() throws {
    let transfer = try proposedResponseTransfer()
    let envelope = try ProposedQRV2ReviewParser.parse(transfer, expectedKind: .response)
    let acceptedEnvelope = try Data(
        hex: String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()
                .appendingPathComponent("../../../../fixtures/protocol-v1/cose/positive-envelope.hex")
                .standardizedFileURL,
            encoding: .utf8
        ).trimmingCharacters(in: .whitespacesAndNewlines)
    )

    #expect(envelope.encoded() == acceptedEnvelope)
}

@Test func proposedV2ReviewRequiresThePreviouslyEnrolledInstallationKey() throws {
    let envelope = try ProposedQRV2ReviewParser.parse(
        proposedResponseTransfer(),
        expectedKind: .response
    )
    let publicKey = try Data(
        hex: String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()
                .appendingPathComponent("../../../../fixtures/protocol-v1/cose/public-key-compressed.hex")
                .standardizedFileURL,
            encoding: .utf8
        ).trimmingCharacters(in: .whitespacesAndNewlines)
    )

    try verifyWithEnrolledKey(
        envelope,
        lookup: ProposedReviewKeyLookup(
            keyID: envelope.keyID,
            compressedPublicKey: publicKey
        )
    )
    #expect(throws: (any Error).self) {
        try verifyWithEnrolledKey(
            envelope,
            lookup: ProposedReviewKeyLookup(
                keyID: Data(repeating: 0, count: 32),
                compressedPublicKey: publicKey
            )
        )
    }
}

@Test func proposedV2ReviewParserRejectsHostileOuterFrames() throws {
    let valid = try proposedResponseTransfer()
    let mutations = [
        valid.replacingOccurrences(of: "PISTIS1:", with: "PISTIS2:"),
        valid + "=",
        valid.replacingOccurrences(of: ".", with: ".A", options: [], range: valid.range(of: ".")),
        String(valid.dropLast()) + "0",
    ]
    for mutation in mutations {
        #expect(throws: (any Error).self) {
            try ProposedQRV2ReviewParser.parse(mutation, expectedKind: .response)
        }
    }
    #expect(throws: (any Error).self) {
        try ProposedQRV2ReviewParser.parse(valid, expectedKind: .challenge)
    }
}

private extension Data {
    init(hex: String) throws {
        guard hex.count.isMultiple(of: 2) else {
            throw ProposedQRV2ReviewParser.Failure.invalid
        }
        self.init()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index ..< next], radix: 16) else {
                throw ProposedQRV2ReviewParser.Failure.invalid
            }
            append(byte)
            index = next
        }
    }
}
