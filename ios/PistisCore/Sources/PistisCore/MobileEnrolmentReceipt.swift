import Crypto
import Foundation

/// Fully authenticated receipt facts. Application storage may be mutated only
/// after this value has been constructed.
public struct VerifiedMobileEnrolmentReceipt: Sendable {
    public let installationID: Data
    public let installationName: String
    public let audience: String
    public let installationKeyID: Data
    public let installationPublicKey: Data
    public let authorityKeyID: Data
    public let userID: Data
    public let externalIdentityID: Data
    public let deviceID: Data
    public let deviceKeyID: Data
    public let fingerprint: Data
    public let policyGeneration: UInt64
    public let revocationGeneration: UInt64
    public let expiresAt: Date
    public let allowedHTTPSHosts: Set<String>
    public let exactReceiptCOSE: Data
}

/// Strict verifier for the accepted purpose-separated authority receipt.
public enum MobileEnrolmentReceiptV1 {
    /// Verify both the device registration and purpose-separated authority
    /// receipt before returning storage-ready facts.
    public static func verify(
        returnedAuthorityBundle: Data,
        returnedRegistrationCOSE: Data,
        receiptCOSE: Data,
        expectedRegistrationCOSE: Data,
        binding: EnrolmentBindingInput,
        now: Date
    ) throws -> VerifiedMobileEnrolmentReceipt {
        guard returnedAuthorityBundle == binding.presentation.authorityBundle,
              returnedRegistrationCOSE == expectedRegistrationCOSE
        else { throw MobileEnrolmentError.wrongBinding }
        try verifyRegistration(expectedRegistrationCOSE, binding: binding)
        let receiptDescriptor = try descriptor(
            binding.presentation.mobileReceiptDescriptor
        )
        let receipt = try CoseSign1.decode(receiptCOSE)
        guard receipt.keyID == receiptDescriptor.keyID else {
            throw MobileEnrolmentError.wrongBinding
        }
        try verifySignature(
            receipt,
            publicKey: receiptDescriptor.publicKey
        )
        return try decodeReceipt(
            receipt.payload,
            exactReceipt: receiptCOSE,
            binding: binding,
            expectedRegistration: expectedRegistrationCOSE,
            expectedAuthorityKeyID: receiptDescriptor.keyID,
            now: now
        )
    }

    private static func verifyRegistration(
        _ exactCOSE: Data,
        binding: EnrolmentBindingInput
    ) throws {
        let registration = try CoseSign1.decode(exactCOSE)
        guard registration.keyID == binding.deviceKeyID else {
            throw MobileEnrolmentError.wrongBinding
        }
        try verifyBindingPayload(registration.payload, against: binding)
        try verifySignature(registration, publicKey: binding.devicePublicKey)
    }

    private static func verifySignature(
        _ cose: CoseSign1,
        publicKey: Data
    ) throws {
        do {
            let key = try P256.Signing.PublicKey(
                compressedRepresentation: publicKey
            )
            let signature = try P256.Signing.ECDSASignature(
                rawRepresentation: cose.signature
            )
            guard key.isValidSignature(
                signature,
                for: cose.signatureStructure()
            ) else { throw MobileEnrolmentError.wrongBinding }
        } catch let error as MobileEnrolmentError {
            throw error
        } catch {
            throw MobileEnrolmentError.wrongBinding
        }
    }

    private static func verifyBindingPayload(
        _ payload: Data,
        against binding: EnrolmentBindingInput
    ) throws {
        var reader = CeremonyCBORReader(payload)
        try reader.requireMap(count: 16)
        try reader.requireUnsigned(0)
        try reader.requireText("pistis.enrolment-binding.v1")
        try reader.requireUnsigned(1)
        let operationID = try reader.bytes(count: 16)
        try reader.requireUnsigned(2)
        let invitationID = try reader.bytes(count: 16)
        try reader.requireUnsigned(3)
        let tenantID = try reader.bytes(count: 16)
        try reader.requireUnsigned(4)
        let principalID = try reader.bytes(count: 16)
        try reader.requireUnsigned(5)
        let installationID = try reader.bytes(count: 16)
        try reader.requireUnsigned(6); try reader.requireText("github.com")
        try reader.requireUnsigned(7)
        let subject = try reader.text(maximum: 20)
        try reader.requireUnsigned(8)
        let publicKey = try reader.bytes(count: 33)
        try reader.requireUnsigned(9)
        let keyID = try reader.bytes(count: 32)
        try reader.requireUnsigned(10); try reader.requireUnsigned(1)
        try reader.requireUnsigned(11); try reader.requireUnsigned(1)
        try reader.requireUnsigned(12)
        let policyGeneration = try reader.unsigned()
        try reader.requireUnsigned(13)
        let appDigest = try reader.bytes(count: 32)
        try reader.requireUnsigned(14)
        let challenge = try reader.bytes(count: 32)
        try reader.requireUnsigned(15)
        let challengeExpiry = try reader.unsigned()
        guard reader.isAtEnd,
              payload == EnrolmentBindingV1.payload(binding),
              operationID == binding.operationID,
              invitationID == binding.presentation.invitationID,
              tenantID == binding.presentation.tenantID,
              principalID == binding.presentation.principalID,
              installationID == binding.presentation.installationID,
              subject == String(binding.numericSubject),
              publicKey == binding.devicePublicKey,
              keyID == binding.deviceKeyID,
              policyGeneration == binding.policyGeneration,
              appDigest == binding.presentation.appConfigurationDigest,
              challenge == binding.authorityChallenge,
              challengeExpiry
                  == binding.authorityChallengeExpiresAtMilliseconds
        else { throw MobileEnrolmentError.wrongBinding }
    }

    private static func decodeReceipt(
        _ payload: Data,
        exactReceipt: Data,
        binding: EnrolmentBindingInput,
        expectedRegistration: Data,
        expectedAuthorityKeyID: Data,
        now: Date
    ) throws -> VerifiedMobileEnrolmentReceipt {
        var reader = CeremonyCBORReader(payload)
        try reader.requireMap(count: 26)
        try reader.requireUnsigned(0); try reader.requireUnsigned(1)
        try reader.requireUnsigned(1)
        try reader.requireText("pistis.mobile-enrolment-receipt.v1")
        try reader.requireUnsigned(2); let issued = try reader.unsigned()
        try reader.requireUnsigned(3); let expires = try reader.unsigned()
        try reader.requireUnsigned(4); let evidenceID = try reader.bytes(count: 16)
        try reader.requireUnsigned(5); let installationID = try reader.bytes(count: 16)
        try reader.requireUnsigned(6); let name = try reader.text(maximum: 128)
        try reader.requireUnsigned(7); let audience = try reader.text(maximum: 128)
        try reader.requireUnsigned(8); let installationKeyID = try reader.bytes(count: 32)
        try reader.requireUnsigned(9); let installationPublicKey = try reader.bytes(count: 33)
        try reader.requireUnsigned(10); try reader.requireNegative(-7)
        try reader.requireUnsigned(11); let fingerprint = try reader.bytes(count: 32)
        try reader.requireUnsigned(12); let authorityKeyID = try reader.bytes(count: 32)
        try reader.requireUnsigned(13); let userID = try reader.bytes(count: 16)
        try reader.requireUnsigned(14); let externalID = try reader.bytes(count: 16)
        try reader.requireUnsigned(15); let deviceID = try reader.bytes(count: 16)
        try reader.requireUnsigned(16); let deviceKeyID = try reader.bytes(count: 32)
        try reader.requireUnsigned(17); let devicePublicKey = try reader.bytes(count: 33)
        try reader.requireUnsigned(18); try reader.requireNegative(-7)
        try reader.requireUnsigned(19)
        try reader.requireText("secure-enclave-biometry-current-set")
        try reader.requireUnsigned(20)
        let registrationDigest = try reader.bytes(count: 32)
        try reader.requireUnsigned(21); let policy = try reader.unsigned()
        try reader.requireUnsigned(22); let revocation = try reader.unsigned()
        try reader.requireUnsigned(23); try reader.requireTrue()
        try reader.requireUnsigned(24); let confirmed = try reader.unsigned()
        try reader.requireUnsigned(25)
        let hosts = try reader.textArray(maximumCount: 16, maximumText: 253)

        let nowMilliseconds = UInt64(now.timeIntervalSince1970 * 1_000)
        let installationFingerprint = Data(
            SHA256.hash(data: installationPublicKey)
        )
        let installationDerivedID = Data(SHA256.hash(
            data: Data("pistis:key-id:v1\0".utf8) + installationPublicKey
        ))
        guard reader.isAtEnd, issued < expires,
              nowMilliseconds >= issued, nowMilliseconds < expires,
              confirmed >= issued, confirmed < expires,
              confirmed <= nowMilliseconds,
              !evidenceID.allSatisfy({ $0 == 0 }),
              !externalID.allSatisfy({ $0 == 0 }),
              !deviceID.allSatisfy({ $0 == 0 }),
              validP256PublicKey(installationPublicKey),
              installationID == binding.presentation.installationID,
              name == binding.presentation.installationName,
              audience == binding.presentation.audience,
              installationKeyID == installationDerivedID,
              fingerprint == installationFingerprint,
              authorityKeyID == expectedAuthorityKeyID,
              userID == binding.presentation.principalID,
              deviceKeyID == binding.deviceKeyID,
              devicePublicKey == binding.devicePublicKey,
              registrationDigest
                  == Data(SHA256.hash(data: expectedRegistration)),
              policy > 0, revocation > 0,
              policy == binding.policyGeneration,
              canonicalHosts(hosts),
              let originHost = binding.presentation.httpsOrigin.host,
              hosts.contains(originHost)
        else { throw MobileEnrolmentError.wrongBinding }
        return VerifiedMobileEnrolmentReceipt(
            installationID: installationID,
            installationName: name,
            audience: audience,
            installationKeyID: installationKeyID,
            installationPublicKey: installationPublicKey,
            authorityKeyID: authorityKeyID,
            userID: userID,
            externalIdentityID: externalID,
            deviceID: deviceID,
            deviceKeyID: deviceKeyID,
            fingerprint: fingerprint,
            policyGeneration: policy,
            revocationGeneration: revocation,
            expiresAt: Date(
                timeIntervalSince1970: TimeInterval(expires) / 1_000
            ),
            allowedHTTPSHosts: Set(hosts),
            exactReceiptCOSE: exactReceipt
        )
    }

    private static func descriptor(_ bytes: Data) throws
        -> (keyID: Data, publicKey: Data)
    {
        var reader = CeremonyCBORReader(bytes)
        try reader.requireMap(count: 5)
        try reader.requireUnsigned(0); try reader.requireUnsigned(1)
        try reader.requireUnsigned(1)
        try reader.requireText("pistis.authority-key-descriptor.v1")
        try reader.requireUnsigned(2); let keyID = try reader.bytes(count: 32)
        try reader.requireUnsigned(3); let publicKey = try reader.bytes(count: 33)
        try reader.requireUnsigned(4); try reader.requireNegative(-7)
        let derived = Data(SHA256.hash(
            data: Data("pistis:key-id:v1\0".utf8) + publicKey
        ))
        guard reader.isAtEnd, derived == keyID else {
            throw MobileEnrolmentError.wrongBinding
        }
        return (keyID, publicKey)
    }

    private static func canonicalHosts(_ hosts: [String]) -> Bool {
        guard !hosts.isEmpty, Set(hosts).count == hosts.count,
              hosts == hosts.sorted() else { return false }
        return hosts.allSatisfy { host in
            host == host.lowercased() && !host.hasSuffix(".")
                && host.unicodeScalars.allSatisfy(\.isASCII)
                && host.split(
                    separator: ".",
                    omittingEmptySubsequences: false
                ).allSatisfy { label in
                    !label.isEmpty && label.first != "-" && label.last != "-"
                        && label.utf8.allSatisfy {
                            (48 ... 57).contains($0)
                                || (97 ... 122).contains($0) || $0 == 45
                        }
                }
        }
    }

    private static func validP256PublicKey(_ bytes: Data) -> Bool {
        let key = try? P256.Signing.PublicKey(
            compressedRepresentation: bytes
        )
        return key?.compressedRepresentation == bytes
    }
}
