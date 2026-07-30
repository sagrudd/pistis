import Crypto
import Foundation

/// An accepted ADR 0029 first-device presentation.
public enum FirstDevicePresentationError: Error, Equatable, Sendable {
    case malformed
    case invalidAuthority
    case invalidSignature
    case wrongConfiguration
    case expired
}

/// Authenticated facts displayed before first-device network use.
public struct VerifiedFirstDevicePresentation: Equatable, Sendable {
    public let presentationID: Data
    public let issuedAtMilliseconds: UInt64
    public let expiresAtMilliseconds: UInt64
    public let authorityID: Data
    public let tenantID: Data
    public let principalID: Data
    public let invitationID: Data
    public let installationID: Data
    public let installationName: String
    /// Fixed purpose audience of the enrolment ceremony.
    public let audience: String
    /// Closed authority-signed product audiences permitted after enrolment.
    public let authorisedProductAudiences: [String]
    public let httpsOrigin: URL
    public let appConfigurationDigest: Data
    /// SHA-256 of the server leaf certificate's exact DER SubjectPublicKeyInfo.
    public let tlsSPKISHA256: Data
    /// Three human-comparable words derived from the authenticated host binding.
    public let trustWords: [String]
    /// SHA-256 of the exact binary version-4 outer frame.
    public let presentationDigest: Data
    /// Exact canonical purpose-separated authority bundle.
    public let authorityBundle: Data
    /// Exact descriptor permitted to sign the attended presentation.
    public let initialInvitationDescriptor: Data
    /// Exact descriptor permitted to sign the final authority receipt.
    public let mobileReceiptDescriptor: Data
    /// Sensitive exact invitation; submit only to the fixed begin route.
    public let exactInvitation: Data
}

/// Accepted version-4/kind-3 QR decoder and authority verifier.
public enum FirstDevicePresentationV4 {
    public static let maximumTextBytes = 2_331

    /// Verify a scanned first-device QR before any network or Keychain use.
    public static func verify(
        qrText: String,
        expectedAppConfigurationDigest: Data,
        now: Date
    ) throws -> VerifiedFirstDevicePresentation {
        guard expectedAppConfigurationDigest.count == 32 else {
            throw FirstDevicePresentationError.wrongConfiguration
        }
        let frame = try decodeTransfer(qrText)
        var outer = CeremonyCBORReader(frame)
        try outer.requireMap(count: 4)
        try outer.requireUnsigned(0); try outer.requireUnsigned(4)
        try outer.requireUnsigned(1); try outer.requireUnsigned(3)
        try outer.requireUnsigned(2)
        let coseBytes = try outer.byteString(maximum: 2_048)
        try outer.requireUnsigned(3)
        let bundleBytes = try outer.byteString(maximum: 512)
        guard outer.isAtEnd else { throw FirstDevicePresentationError.malformed }

        let bundle = try decodeBundle(bundleBytes)
        let descriptor = bundle.initial
        let actualKeyID = Data(SHA256.hash(
            data: Data("pistis:key-id:v1\0".utf8) + descriptor.publicKey
        ))
        guard descriptor.keyID == actualKeyID else {
            throw FirstDevicePresentationError.invalidAuthority
        }
        let cose = try CoseSign1.decode(coseBytes)
        guard cose.keyID == descriptor.keyID else {
            throw FirstDevicePresentationError.invalidAuthority
        }
        do {
            let publicKey = try P256.Signing.PublicKey(
                compressedRepresentation: descriptor.publicKey
            )
            let signature = try P256.Signing.ECDSASignature(
                rawRepresentation: cose.signature
            )
            guard publicKey.isValidSignature(signature, for: cose.signatureStructure()) else {
                throw FirstDevicePresentationError.invalidSignature
            }
        } catch let error as FirstDevicePresentationError {
            throw error
        } catch {
            throw FirstDevicePresentationError.invalidSignature
        }

        var payload = CeremonyCBORReader(cose.payload)
        try payload.requireMap(count: 18)
        try payload.requireUnsigned(0); try payload.requireUnsigned(3)
        try payload.requireUnsigned(1)
        try payload.requireText("pistis.first-device-presentation.v3")
        try payload.requireUnsigned(2); let presentationID = try payload.bytes(count: 16)
        try payload.requireUnsigned(3); let issued = try payload.unsigned()
        try payload.requireUnsigned(4); let expires = try payload.unsigned()
        try payload.requireUnsigned(5); let invitationBytes = try payload.byteString(maximum: 512)
        let invitation = try decodeInvitation(invitationBytes)
        try payload.requireUnsigned(6); let authorityID = try payload.bytes(count: 16)
        try payload.requireUnsigned(7); let tenantID = try payload.bytes(count: 16)
        try payload.requireUnsigned(8); let principalID = try payload.bytes(count: 16)
        try payload.requireUnsigned(9); let installationID = try payload.bytes(count: 16)
        try payload.requireUnsigned(10); let installationName = try payload.text(maximum: 128)
        try payload.requireUnsigned(11); let audience = try payload.text(maximum: 128)
        try payload.requireUnsigned(12); let originText = try payload.text(maximum: 255)
        try payload.requireUnsigned(13); let appDigest = try payload.bytes(count: 32)
        try payload.requireUnsigned(14); let descriptorDigest = try payload.bytes(count: 32)
        try payload.requireUnsigned(15); let tlsSPKISHA256 = try payload.bytes(count: 32)
        try payload.requireUnsigned(16)
        try payload.requireUnsigned(HostTrustWordsV1.version)
        try payload.requireUnsigned(17)
        let authorisedProductAudiences = try payload.textArray(
            maximumCount: 3,
            maximumText: 128
        )
        guard payload.isAtEnd,
              !presentationID.allSatisfy({ $0 == 0 }),
              !authorityID.allSatisfy({ $0 == 0 }),
              !tenantID.allSatisfy({ $0 == 0 }),
              !principalID.allSatisfy({ $0 == 0 }),
              !installationID.allSatisfy({ $0 == 0 }),
              !installationName.isEmpty,
              installationName
                  == installationName.trimmingCharacters(
                      in: .whitespacesAndNewlines
                  ),
              !audience.isEmpty
                  && canonicalProductAudiences(authorisedProductAudiences)
        else { throw FirstDevicePresentationError.malformed }

        let actualDescriptorDigest = Data(SHA256.hash(data: bundleBytes))
        guard invitation.installationID == installationID,
              invitation.audience == audience,
              invitation.authorisedProductAudiences == authorisedProductAudiences,
              invitation.descriptorDigest == actualDescriptorDigest,
              descriptorDigest == actualDescriptorDigest
        else { throw FirstDevicePresentationError.invalidAuthority }
        guard appDigest == expectedAppConfigurationDigest else {
            throw FirstDevicePresentationError.wrongConfiguration
        }
        let nowMilliseconds = UInt64(now.timeIntervalSince1970 * 1_000)
        guard issued < expires, nowMilliseconds >= issued,
              nowMilliseconds < expires, expires <= invitation.expires
        else { throw FirstDevicePresentationError.expired }
        let origin = try canonicalOrigin(originText)
        let trustWords = try HostTrustWordsV1.derive(
            authorityID: authorityID,
            installationID: installationID,
            httpsOrigin: originText,
            tlsSPKISHA256: tlsSPKISHA256,
            appConfigurationDigest: appDigest
        )
        return VerifiedFirstDevicePresentation(
            presentationID: presentationID,
            issuedAtMilliseconds: issued,
            expiresAtMilliseconds: expires,
            authorityID: authorityID,
            tenantID: tenantID,
            principalID: principalID,
            invitationID: invitation.id,
            installationID: installationID,
            installationName: installationName,
            audience: audience,
            authorisedProductAudiences: authorisedProductAudiences,
            httpsOrigin: origin,
            appConfigurationDigest: appDigest,
            tlsSPKISHA256: tlsSPKISHA256,
            trustWords: trustWords,
            presentationDigest: Data(SHA256.hash(data: frame)),
            authorityBundle: bundleBytes,
            initialInvitationDescriptor: bundle.initialBytes,
            mobileReceiptDescriptor: bundle.receiptBytes,
            exactInvitation: invitationBytes
        )
    }

    private static func decodeTransfer(_ text: String) throws -> Data {
        guard text.utf8.count <= maximumTextBytes,
              text.unicodeScalars.allSatisfy(\.isASCII),
              text.hasPrefix("PISTIS1:"),
              let separator = text.lastIndex(of: ".")
        else { throw FirstDevicePresentationError.malformed }
        let body = String(text[text.index(text.startIndex, offsetBy: 8) ..< separator])
        let checksum = String(text[text.index(after: separator)...])
        guard !body.isEmpty, checksum.count == 16,
              body.utf8.allSatisfy({
                  (48 ... 57).contains($0) || (65 ... 90).contains($0)
                      || (97 ... 122).contains($0) || $0 == 45 || $0 == 95
              }),
              checksum.utf8.allSatisfy({
                  (48 ... 57).contains($0) || (97 ... 102).contains($0)
              })
        else { throw FirstDevicePresentationError.malformed }
        let expected = SHA256.hash(data: Data("PISTIS1:\(body)".utf8)).prefix(8)
            .map { String(format: "%02x", $0) }.joined()
        guard checksum == expected else { throw FirstDevicePresentationError.malformed }
        var padded = body.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        padded += String(repeating: "=", count: (4 - padded.count % 4) % 4)
        guard let result = Data(base64Encoded: padded), result.count <= 1_728 else {
            throw FirstDevicePresentationError.malformed
        }
        return result
    }

    private static func decodeDescriptor(_ bytes: Data) throws
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
        guard reader.isAtEnd else { throw FirstDevicePresentationError.invalidAuthority }
        return (keyID, publicKey)
    }

    private static func decodeBundle(_ bytes: Data) throws
        -> (
            initial: (keyID: Data, publicKey: Data),
            receipt: (keyID: Data, publicKey: Data),
            initialBytes: Data,
            receiptBytes: Data
        )
    {
        var reader = CeremonyCBORReader(bytes)
        try reader.requireMap(count: 4)
        try reader.requireUnsigned(0); try reader.requireUnsigned(1)
        try reader.requireUnsigned(1)
        try reader.requireText("pistis.first-device-authority-bundle.v1")
        try reader.requireUnsigned(2)
        let initialBytes = try reader.byteString(maximum: 256)
        try reader.requireUnsigned(3)
        let receiptBytes = try reader.byteString(maximum: 256)
        guard reader.isAtEnd else {
            throw FirstDevicePresentationError.invalidAuthority
        }
        let initial = try decodeDescriptor(initialBytes)
        let receipt = try decodeDescriptor(receiptBytes)
        let initialID = Data(SHA256.hash(
            data: Data("pistis:key-id:v1\0".utf8) + initial.publicKey
        ))
        let receiptID = Data(SHA256.hash(
            data: Data("pistis:key-id:v1\0".utf8) + receipt.publicKey
        ))
        guard initial.keyID == initialID, receipt.keyID == receiptID,
              initial.keyID != receipt.keyID
        else { throw FirstDevicePresentationError.invalidAuthority }
        return (initial, receipt, initialBytes, receiptBytes)
    }

    private static func decodeInvitation(_ bytes: Data) throws
        -> (
            id: Data,
            expires: UInt64,
            installationID: Data,
            audience: String,
            descriptorDigest: Data,
            authorisedProductAudiences: [String]
        )
    {
        var reader = CeremonyCBORReader(bytes)
        try reader.requireMap(count: 10)
        try reader.requireUnsigned(0); try reader.requireUnsigned(2)
        try reader.requireUnsigned(1)
        try reader.requireText("pistis.mobile-enrolment-invitation.v2")
        try reader.requireUnsigned(2); let issued = try reader.unsigned()
        try reader.requireUnsigned(3); let expires = try reader.unsigned()
        try reader.requireUnsigned(4); let id = try reader.bytes(count: 16)
        try reader.requireUnsigned(5); _ = try reader.bytes(count: 32)
        try reader.requireUnsigned(6); let installationID = try reader.bytes(count: 16)
        try reader.requireUnsigned(7); let audience = try reader.text(maximum: 128)
        try reader.requireUnsigned(8); let digest = try reader.bytes(count: 32)
        try reader.requireUnsigned(9)
        let authorisedProductAudiences = try reader.textArray(
            maximumCount: 3,
            maximumText: 128
        )
        guard reader.isAtEnd, issued < expires,
              !id.allSatisfy({ $0 == 0 }),
              !installationID.allSatisfy({ $0 == 0 }),
              !audience.isEmpty,
              canonicalProductAudiences(authorisedProductAudiences)
        else {
            throw FirstDevicePresentationError.malformed
        }
        return (
            id,
            expires,
            installationID,
            audience,
            digest,
            authorisedProductAudiences
        )
    }

    private static func canonicalProductAudiences(_ audiences: [String]) -> Bool {
        let supported = Set(["dasobjectstore", "jenkins", "propylaion"])
        return !audiences.isEmpty
            && Set(audiences).count == audiences.count
            && audiences == audiences.sorted()
            && audiences.allSatisfy {
                supported.contains($0)
                    && !$0.isEmpty
                    && $0.utf8.count <= 128
                    && $0.unicodeScalars.allSatisfy(\.isASCII)
            }
    }

    private static func canonicalOrigin(_ text: String) throws -> URL {
        guard text == text.lowercased(), text.unicodeScalars.allSatisfy(\.isASCII),
              !text.contains("%"), let url = URL(string: text),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme == "https", components.user == nil,
              components.password == nil, components.path.isEmpty,
              components.query == nil, components.fragment == nil,
              let host = components.host, components.percentEncodedHost == host,
              !host.hasSuffix("."), !host.contains(":"),
              !host.split(separator: ".", omittingEmptySubsequences: false).contains(where: {
                  $0.isEmpty || $0.first == "-" || $0.last == "-"
                      || !$0.utf8.allSatisfy {
                          (48 ... 57).contains($0) || (97 ... 122).contains($0) || $0 == 45
                      }
              }),
              components.port != 443, components.string == text
        else { throw FirstDevicePresentationError.malformed }
        return url
    }
}
