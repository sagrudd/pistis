import CryptoKit
import Foundation
import XCTest
@testable import Pistis

/// Test-only ceremony support for collecting non-secret EPIC-18 evidence.
///
/// This harness neither creates a COSE envelope nor registers an identity.
/// It signs the committed public `Sig_structure` fixture solely so that the
/// independent Rust verifier can check the physical Secure Enclave boundary.
struct DeviceInteroperabilityHarness {
    static let keyIDDomain = Data("pistis:key-id:v1\0".utf8)

    let signatureStructure: Data

    init(signatureStructure: Data) throws {
        guard signatureStructure.count <= 65_536 + 128 else {
            throw HarnessFailure.invalidFixture
        }
        self.signatureStructure = signatureStructure
    }

    /// Run one physical-device observation using an explicitly test-only key
    /// namespace. The result contains no private key, biometric, identifier,
    /// challenge nonce, or production authority.
    func observe() throws -> DeviceInteroperabilityRecord {
        let signer = try SecureEnclaveSigner(
            namespace: "test-only-epic18-cose-interoperability-v1",
            authenticationReason: "Sign the non-production Pistis interoperability fixture."
        )
        let observation = try signer.interoperabilityProbe(
            signatureStructure: signatureStructure
        )
        return try DeviceInteroperabilityRecord(
            publicKey: observation.publicKey,
            signatureStructure: observation.signatureStructure,
            rawES256Signature: observation.rawES256Signature
        )
    }

    /// Decode the pinned text resource as the exact bytes signed by the
    /// physical-device ceremony. The digest prevents a local resource change
    /// from silently changing what the test asks a user to authorize.
    static func fixture(from bundle: Bundle) throws -> DeviceInteroperabilityHarness {
        guard let url = bundle.url(forResource: "signing-input", withExtension: "hex") else {
            throw HarnessFailure.fixtureUnavailable
        }
        let text = try String(contentsOf: url, encoding: .utf8)
        let bytes = try decodeLowercaseHex(text)
        guard Data(SHA256.hash(data: bytes)) == fixtureDigest else {
            throw HarnessFailure.fixtureIntegrityFailed
        }
        return try Self(signatureStructure: bytes)
    }

    private static let fixtureDigest = Data([
        0x52, 0x33, 0x27, 0x8b, 0x36, 0x33, 0xc2, 0x02,
        0xd1, 0x9c, 0xbc, 0x5d, 0xeb, 0xb9, 0x2e, 0x69,
        0x4a, 0x8f, 0xec, 0x23, 0xd9, 0x1f, 0xad, 0xd6,
        0xdb, 0x3b, 0x1c, 0x2b, 0xb1, 0x61, 0x90, 0x4e,
    ])

    private static func decodeLowercaseHex(_ text: String) throws -> Data {
        let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty,
              value.count.isMultiple(of: 2),
              value.unicodeScalars.allSatisfy({
                  ("0" ... "9").contains(Character($0))
                      || ("a" ... "f").contains(Character($0))
              })
        else {
            throw HarnessFailure.invalidFixture
        }

        var bytes = Data()
        bytes.reserveCapacity(value.count / 2)
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index ..< next], radix: 16) else {
                throw HarnessFailure.invalidFixture
            }
            bytes.append(byte)
            index = next
        }
        return bytes
    }
}

/// Redacted, independently verifiable physical-device observation.
///
/// This is deliberately the complete emitted schema. Do not extend it with
/// device serials, biometric details, Apple credentials, or private material.
struct DeviceInteroperabilityRecord: Codable, Equatable, Sendable {
    let publicKeyCompressedSEC1Hex: String
    let keyIDHex: String
    let signatureStructureSHA256Hex: String
    let signatureStructureHex: String
    let rawES256SignatureHex: String

    init(
        publicKey: DevicePublicKey,
        signatureStructure: Data,
        rawES256Signature: Data
    ) throws {
        guard publicKey.assurance == .secureEnclaveBiometryCurrentSet,
              publicKey.compressedSEC1.count == 33,
              publicKey.compressedSEC1.first == 0x02 || publicKey.compressedSEC1.first == 0x03,
              // CryptoKit's compact representation is the x-coordinate, not
              // SEC1's leading parity byte plus x-coordinate. Rust remains
              // the independent verifier for the complete SEC1 encoding.
              (try? P256.Signing.PublicKey(
                  compactRepresentation: publicKey.compressedSEC1.dropFirst()
              )) != nil,
              !signatureStructure.isEmpty,
              P256Format.isCanonicalRawSignature(rawES256Signature)
        else {
            throw HarnessFailure.invalidObservation
        }

        let keyID = SHA256.hash(data: DeviceInteroperabilityHarness.keyIDDomain + publicKey.compressedSEC1)
        publicKeyCompressedSEC1Hex = publicKey.compressedSEC1.lowercaseHex
        keyIDHex = Data(keyID).lowercaseHex
        signatureStructureSHA256Hex = Data(SHA256.hash(data: signatureStructure)).lowercaseHex
        signatureStructureHex = signatureStructure.lowercaseHex
        rawES256SignatureHex = rawES256Signature.lowercaseHex
    }

    func renderedJSON() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let output = String(data: try encoder.encode(self), encoding: .utf8) else {
            throw HarnessFailure.invalidObservation
        }
        return output
    }
}

enum HarnessFailure: Error, Equatable {
    case fixtureUnavailable
    case invalidFixture
    case fixtureIntegrityFailed
    case invalidObservation
}

private extension Data {
    var lowercaseHex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
