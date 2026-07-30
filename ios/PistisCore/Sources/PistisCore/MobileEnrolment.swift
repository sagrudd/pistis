import Crypto
import Foundation

public enum MobileEnrolmentError: Error, Equatable, Sendable {
    case wrongBinding
}

/// Locally known inputs to the accepted ADR 0025 signed binding.
public struct EnrolmentBindingInput: Sendable {
    public let operationID: Data
    public let presentation: VerifiedFirstDevicePresentation
    public let numericSubject: UInt64
    public let devicePublicKey: Data
    public let deviceKeyID: Data
    public let policyGeneration: UInt64
    public let authorityChallenge: Data
    public let authorityChallengeExpiresAtMilliseconds: UInt64

    public init(
        operationID: Data,
        presentation: VerifiedFirstDevicePresentation,
        numericSubject: UInt64,
        devicePublicKey: Data,
        deviceKeyID: Data,
        policyGeneration: UInt64,
        authorityChallenge: Data,
        authorityChallengeExpiresAtMilliseconds: UInt64
    ) throws {
        let parsedDeviceKey = try? P256.Signing.PublicKey(
            compressedRepresentation: devicePublicKey
        )
        let derivedKeyID = Data(SHA256.hash(
            data: Data("pistis:key-id:v1\0".utf8) + devicePublicKey
        ))
        guard operationID.count == 16,
              !operationID.allSatisfy({ $0 == 0 }),
              numericSubject > 0,
              devicePublicKey.count == 33, deviceKeyID.count == 32,
              parsedDeviceKey?.compressedRepresentation == devicePublicKey,
              deviceKeyID == derivedKeyID,
              policyGeneration > 0,
              authorityChallenge.count == 32,
              authorityChallengeExpiresAtMilliseconds
                  <= presentation.expiresAtMilliseconds
        else { throw MobileEnrolmentError.wrongBinding }
        self.operationID = operationID
        self.presentation = presentation
        self.numericSubject = numericSubject
        self.devicePublicKey = devicePublicKey
        self.deviceKeyID = deviceKeyID
        self.policyGeneration = policyGeneration
        self.authorityChallenge = authorityChallenge
        self.authorityChallengeExpiresAtMilliseconds =
            authorityChallengeExpiresAtMilliseconds
    }
}

public enum EnrolmentBindingV1 {
    /// Deterministic CBOR payload signed by the device-bound key.
    public static func payload(_ input: EnrolmentBindingInput) -> Data {
        var output = Data([0xb0])
        output.append(MobileCBOR.unsigned(0))
        output.append(MobileCBOR.text("pistis.enrolment-binding.v1"))
        output.append(MobileCBOR.unsigned(1))
        output.append(MobileCBOR.bytes(input.operationID))
        output.append(MobileCBOR.unsigned(2))
        output.append(MobileCBOR.bytes(input.presentation.invitationID))
        output.append(MobileCBOR.unsigned(3))
        output.append(MobileCBOR.bytes(input.presentation.tenantID))
        output.append(MobileCBOR.unsigned(4))
        output.append(MobileCBOR.bytes(input.presentation.principalID))
        output.append(MobileCBOR.unsigned(5))
        output.append(MobileCBOR.bytes(input.presentation.installationID))
        output.append(MobileCBOR.unsigned(6))
        output.append(MobileCBOR.text("github.com"))
        output.append(MobileCBOR.unsigned(7))
        output.append(MobileCBOR.text(String(input.numericSubject)))
        output.append(MobileCBOR.unsigned(8))
        output.append(MobileCBOR.bytes(input.devicePublicKey))
        output.append(MobileCBOR.unsigned(9))
        output.append(MobileCBOR.bytes(input.deviceKeyID))
        output.append(MobileCBOR.unsigned(10))
        output.append(MobileCBOR.unsigned(1))
        output.append(MobileCBOR.unsigned(11))
        output.append(MobileCBOR.unsigned(1))
        output.append(MobileCBOR.unsigned(12))
        output.append(MobileCBOR.unsigned(input.policyGeneration))
        output.append(MobileCBOR.unsigned(13))
        output.append(MobileCBOR.bytes(input.presentation.appConfigurationDigest))
        output.append(MobileCBOR.unsigned(14))
        output.append(MobileCBOR.bytes(input.authorityChallenge))
        output.append(MobileCBOR.unsigned(15))
        output.append(
            MobileCBOR.unsigned(input.authorityChallengeExpiresAtMilliseconds)
        )
        return output
    }
}

private enum MobileCBOR {
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
