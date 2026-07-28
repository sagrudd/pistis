import Foundation

#if canImport(LocalAuthentication) && canImport(Security)
import LocalAuthentication
import Security

/// Public information about a device-bound signing key.
struct DevicePublicKey: Equatable, Sendable {
    /// Compressed SEC1 representation of a NIST P-256 public key.
    let compressedSEC1: Data

    /// Assurance this adapter can truthfully report for the key.
    let assurance: KeyAssurance
}

enum KeyAssurance: String, Equatable, Sendable {
    case secureEnclaveFaceIDCurrentSet
}

/// Non-secret output from one physical-device interoperability probe.
///
/// This value is input to offline Rust verification and the reviewed evidence
/// record. Its presence alone is not an acceptance result: the record must
/// still bind the source revision, Xcode/iOS versions, device class, key
/// fingerprint, verifier result, and reviewer.
struct DeviceInteroperabilityObservation: Equatable, Sendable {
    let publicKey: DevicePublicKey
    let signatureStructure: Data
    let rawES256Signature: Data
}

/// Secure Enclave P-256 signing with fresh local authentication per operation.
///
/// The adapter never exports private-key bytes and never falls back to a
/// software key. A missing or invalidated key requires explicit device
/// re-enrolment by the caller.
final class SecureEnclaveSigner: @unchecked Sendable {
    private let applicationTag: Data
    private let authenticationReason: String

    init(namespace: String, authenticationReason: String) throws {
        guard !namespace.isEmpty,
              namespace.utf8.count <= 128,
              !authenticationReason.isEmpty
        else {
            throw PlatformFailure.invalidConfiguration
        }
        self.applicationTag = Data("org.mnemosyne.pistis.device-key.\(namespace)".utf8)
        self.authenticationReason = authenticationReason
    }

    func create() throws -> DevicePublicKey {
        guard SecureEnclaveSigner.secureEnclaveIsAvailable else {
            throw PlatformFailure.secureHardwareUnavailable
        }
        try requireFaceID(using: LAContext())
        if try keyExists() {
            return try publicKey()
        }

        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &accessError
        ) else {
            throw PlatformFailure.keyCreationFailed
        }

        let privateAttributes: [CFString: Any] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: applicationTag,
            kSecAttrAccessControl: access,
        ]
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: privateAttributes,
        ]

        var creationError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(
            attributes as CFDictionary,
            &creationError
        ) else {
            throw PlatformFailure.keyCreationFailed
        }
        return try devicePublicKey(from: privateKey)
    }

    func publicKey() throws -> DevicePublicKey {
        let context = LAContext()
        context.localizedReason = authenticationReason
        guard let privateKey = try findPrivateKey(authenticationContext: context) else {
            throw PlatformFailure.keyNotFound
        }
        return try devicePublicKey(from: privateKey)
    }

    /// Whether the namespaced device-bound key already exists.
    ///
    /// This query never returns key bytes and is used only for coarse
    /// readiness presentation. It does not create a key or grant authority.
    func hasExistingKey() throws -> Bool {
        try keyExists()
    }

    private func devicePublicKey(from privateKey: SecKey) throws -> DevicePublicKey {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw PlatformFailure.publicKeyExtractionFailed
        }
        var extractionError: Unmanaged<CFError>?
        guard let representation = SecKeyCopyExternalRepresentation(
            publicKey,
            &extractionError
        ) as Data? else {
            throw PlatformFailure.publicKeyExtractionFailed
        }
        return DevicePublicKey(
            compressedSEC1: try P256Format.compressX963PublicKey(representation),
            assurance: .secureEnclaveFaceIDCurrentSet
        )
    }

    /// Signs one exact message and returns fixed-width `r || s`.
    ///
    /// A new `LAContext` is deliberately created for every call. The returned
    /// raw proof material is assembled by the accepted COSE profile; this
    /// platform adapter does not itself issue authentication authority.
    func sign(message: Data) throws -> Data {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        context.localizedReason = authenticationReason
        context.interactionNotAllowed = false
        try requireFaceID(using: context)

        guard let privateKey = try findPrivateKey(authenticationContext: context) else {
            throw PlatformFailure.keyNotFound
        }
        var signingError: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &signingError
        ) as Data? else {
            throw mapSecurityError(signingError?.takeRetainedValue())
        }
        return try P256Format.rawSignature(fromStrictDER: der)
    }

    /// Exercise the real Secure Enclave and local-biometry path for an exact
    /// precomputed COSE `Sig_structure`.
    ///
    /// The simulator fails closed during `create()`. This probe deliberately
    /// does not declare interoperability successful; its non-secret output
    /// must be verified by the independent Rust implementation and retained
    /// through the authoritative evidence workflow.
    func interoperabilityProbe(signatureStructure: Data) throws
        -> DeviceInteroperabilityObservation
    {
        guard !signatureStructure.isEmpty,
              signatureStructure.count <= 65_536 + 128
        else {
            throw PlatformFailure.invalidConfiguration
        }
        // EPIC-18 acceptance specifically requires Face ID evidence. A
        // successful generic biometric policy can otherwise be satisfied by
        // Touch ID and must not be relabelled as a Face ID ceremony.
        let faceIDContext = LAContext()
        try requireFaceID(using: faceIDContext)
        let publicKey = try create()
        let signature = try sign(message: signatureStructure)
        return DeviceInteroperabilityObservation(
            publicKey: publicKey,
            signatureStructure: signatureStructure,
            rawES256Signature: signature
        )
    }

    private func requireAvailableBiometry(using context: LAContext) throws {
        var evaluationError: NSError?
        guard context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &evaluationError
        ) else {
            guard let code = evaluationError.flatMap({
                LAError.Code(rawValue: $0.code)
            }) else {
                throw PlatformFailure.userVerificationUnavailable
            }
            switch code {
            case .biometryNotEnrolled:
                throw PlatformFailure.userVerificationNotEnrolled
            case .biometryLockout:
                throw PlatformFailure.userVerificationLockedOut
            case .userCancel, .appCancel, .systemCancel:
                throw PlatformFailure.userVerificationCancelled
            default:
                throw PlatformFailure.userVerificationUnavailable
            }
        }
    }

    /// Require Face ID without permitting device-passcode or Touch ID fallback.
    ///
    /// `canEvaluatePolicy` populates `biometryType`; checking it after the
    /// biometric-only policy is available ensures every call to `sign` has the
    /// assurance claimed by the production iPhone profile.
    private func requireFaceID(using context: LAContext) throws {
        try requireAvailableBiometry(using: context)
        guard Self.isFaceID(context.biometryType) else {
            throw PlatformFailure.userVerificationUnavailable
        }
    }

    /// Whether an evaluated LocalAuthentication context reports Face ID.
    ///
    /// Kept separate from policy availability so the physical ceremony can
    /// reject Touch ID rather than treating it as interchangeable evidence.
    static func isFaceID(_ biometryType: LABiometryType) -> Bool {
        biometryType == .faceID
    }

    private func findPrivateKey(authenticationContext: LAContext) throws -> SecKey? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag: applicationTag,
            kSecReturnRef: true,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecUseAuthenticationContext: authenticationContext,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            return nil
        case errSecAuthFailed:
            throw PlatformFailure.keyInvalidated
        case errSecUserCanceled:
            throw PlatformFailure.userVerificationCancelled
        default:
            throw PlatformFailure.signingFailed
        }
    }

    private func keyExists() throws -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag: applicationTag,
            kSecReturnRef: true,
            kSecMatchLimit: kSecMatchLimitOne,
            kSecUseAuthenticationContext: context,
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        switch status {
        case errSecSuccess, errSecInteractionNotAllowed:
            return true
        case errSecItemNotFound:
            return false
        case errSecAuthFailed:
            throw PlatformFailure.keyInvalidated
        default:
            throw PlatformFailure.signingFailed
        }
    }

    private func mapSecurityError(_ error: CFError?) -> PlatformFailure {
        guard let error else { return .signingFailed }
        let code = CFErrorGetCode(error)
        switch code {
        case Int(errSecUserCanceled):
            return .userVerificationCancelled
        case Int(errSecAuthFailed):
            return .keyInvalidated
        case Int(errSecInteractionNotAllowed):
            return .userVerificationUnavailable
        default:
            return .signingFailed
        }
    }

    private static var secureEnclaveIsAvailable: Bool {
        #if targetEnvironment(simulator)
        false
        #else
        true
        #endif
    }
}
#endif

/// Strict P-256 wire-format conversion independent from UI and key storage.
enum P256Format {
    static func compressX963PublicKey(_ bytes: Data) throws -> Data {
        guard bytes.count == 65, bytes.first == 0x04 else {
            throw PlatformFailure.publicKeyExtractionFailed
        }
        var compressed = Data([bytes[64].isMultiple(of: 2) ? 0x02 : 0x03])
        compressed.append(bytes[1...32])
        return compressed
    }

    static func rawSignature(fromStrictDER der: Data) throws -> Data {
        let bytes = [UInt8](der)
        guard bytes.count >= 8, bytes[0] == 0x30 else {
            throw PlatformFailure.malformedSignature
        }
        var offset = 1
        let sequenceLength = try readLength(bytes, offset: &offset)
        guard sequenceLength == bytes.count - offset else {
            throw PlatformFailure.malformedSignature
        }
        let r = try readInteger(bytes, offset: &offset)
        let s = try readInteger(bytes, offset: &offset)
        guard offset == bytes.count else {
            throw PlatformFailure.malformedSignature
        }
        return try fixedWidth(r) + normalizeLowS(try fixedWidth(s))
    }

    /// Whether `signature` is one canonical fixed-width low-S ES256 proof.
    ///
    /// This supports test-only evidence validation; it never verifies a
    /// message or grants product authority.
    static func isCanonicalRawSignature(_ signature: Data) -> Bool {
        guard signature.count == 64 else { return false }
        guard (try? fixedWidth(Array(signature.prefix(32)))) != nil,
              let s = try? fixedWidth(Array(signature.suffix(32)))
        else {
            return false
        }
        return !halfOrder.lexicographicallyPrecedes(s)
    }

    private static func readLength(_ bytes: [UInt8], offset: inout Int) throws -> Int {
        guard offset < bytes.count else { throw PlatformFailure.malformedSignature }
        let first = bytes[offset]
        offset += 1
        if first < 0x80 { return Int(first) }
        let count = Int(first & 0x7f)
        guard count == 1, offset < bytes.count, bytes[offset] >= 0x80 else {
            throw PlatformFailure.malformedSignature
        }
        let result = Int(bytes[offset])
        offset += 1
        return result
    }

    private static func readInteger(_ bytes: [UInt8], offset: inout Int) throws -> [UInt8] {
        guard offset < bytes.count, bytes[offset] == 0x02 else {
            throw PlatformFailure.malformedSignature
        }
        offset += 1
        let length = try readLength(bytes, offset: &offset)
        guard length > 0, offset + length <= bytes.count else {
            throw PlatformFailure.malformedSignature
        }
        let integer = Array(bytes[offset ..< offset + length])
        offset += length
        guard integer[0] & 0x80 == 0,
              !(integer.count > 1 && integer[0] == 0 && integer[1] & 0x80 == 0),
              integer.count <= 33,
              !(integer.count == 33 && integer[0] != 0)
        else {
            throw PlatformFailure.malformedSignature
        }
        return integer
    }

    private static func fixedWidth(_ integer: [UInt8]) throws -> Data {
        let magnitude = integer.first == 0 ? Array(integer.dropFirst()) : integer
        guard magnitude.count <= 32 else { throw PlatformFailure.malformedSignature }
        let scalar = Data(repeating: 0, count: 32 - magnitude.count) + Data(magnitude)
        let order = Data([
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
        ])
        guard scalar.contains(where: { $0 != 0 }),
              scalar.lexicographicallyPrecedes(order)
        else {
            throw PlatformFailure.malformedSignature
        }
        return scalar
    }

    private static func normalizeLowS(_ scalar: Data) -> Data {
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
            if difference < 0 {
                difference += 256
                borrow = 1
            } else {
                borrow = 0
            }
            result[index] = UInt8(difference)
        }
        return Data(result)
    }

    private static let halfOrder = Data([
            0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42,
            0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
        ])
}
