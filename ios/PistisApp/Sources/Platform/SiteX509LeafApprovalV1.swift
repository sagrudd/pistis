import Foundation

enum SiteX509LeafApprovalProfileV1 {
    static let purpose = "proxenos.site-x509-initial-leaf-issuance.v1"
    static let contentType = "application/vnd.mnemosyne.pxla.v1"
    static let beginSchema = "monas.site-x509-leaf-approval-begin.v1"
    static let presentationSchema = "monas.site-x509-leaf-approval-presentation.v1"
    static let submitSchema = "monas.site-x509-leaf-approval-submit.v1"
    static let acceptedSchema = "monas.site-x509-leaf-approval-accepted.v1"
    static let presentationPath = "/v1/pistis/site-x509-leaf-approval/presentation"
    static let submitPath = "/v1/pistis/site-x509-leaf-approval/submit"
}

struct SiteX509LeafApprovalBeginV1: Encodable, Sendable {
    let schema = SiteX509LeafApprovalProfileV1.beginSchema
    let delegationSerial: String
    let delegationExpiresAt: UInt64

    enum CodingKeys: String, CodingKey {
        case schema
        case delegationSerial = "delegation_serial"
        case delegationExpiresAt = "delegation_expires_at"
    }
}

/// Strict, operation-fixed combined approval for the first DAS and Monas
/// private-IP certificates. The exact PXLA bytes are parsed locally before the
/// enrolled PXRA acknowledgement key is allowed to sign them.
struct SiteX509LeafApprovalPresentationV1: Sendable {
    let correlationID: Data
    let canonicalPayload: Data
    let transactionID: Data
    let deviceKeyGeneration: UInt64
    let delegationSerial: String
    let delegationExpiresAt: UInt64
    let siteUUID: Data

    init(data: Data, nowUnixSeconds: UInt64) throws {
        let wire: Wire
        do { wire = try JSONDecoder().decode(Wire.self, from: data) }
        catch { throw PlatformFailure.siteRootAuthorityUnavailable }
        guard wire.schema == SiteX509LeafApprovalProfileV1.presentationSchema,
              wire.purpose == SiteX509LeafApprovalProfileV1.purpose,
              Self.identifier(wire.delegationSerial), wire.deviceKeyGeneration > 0,
              wire.delegationExpiresAt > nowUnixSeconds,
              let correlation = Self.standardBase64(wire.correlationIDB64, count: 16),
              !correlation.allSatisfy({ $0 == 0 }),
              let payload = Self.standardBase64(wire.canonicalPayloadB64, range: 1 ... 4_096),
              let transaction = Self.standardBase64(wire.transactionIDB64, count: 16),
              !transaction.allSatisfy({ $0 == 0 })
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        let parsed = try PXLA(payload)
        guard parsed.transactionID == transaction,
              parsed.deviceKeyGeneration == wire.deviceKeyGeneration,
              parsed.expiresAt > nowUnixSeconds,
              parsed.issuedAt <= nowUnixSeconds,
              parsed.expiresAt - parsed.issuedAt <= 300
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
        correlationID = correlation
        canonicalPayload = payload
        transactionID = transaction
        deviceKeyGeneration = wire.deviceKeyGeneration
        delegationSerial = wire.delegationSerial
        delegationExpiresAt = wire.delegationExpiresAt
        siteUUID = parsed.siteUUID
    }

    func validateCurrentSigner(_ record: SiteRootConvergenceAckRecordV2) throws {
        guard record.generation == deviceKeyGeneration,
              Self.uuid(record.siteUUID) == siteUUID else {
            throw PlatformFailure.siteRootAuthorityUnavailable
        }
    }

    private struct Wire: Decodable {
        let schema: String
        let correlationIDB64: String
        let canonicalPayloadB64: String
        let transactionIDB64: String
        let deviceKeyGeneration: UInt64
        let delegationSerial: String
        let delegationExpiresAt: UInt64
        let purpose: String

        enum CodingKeys: String, CodingKey, CaseIterable {
            case schema, purpose
            case correlationIDB64 = "correlation_id_b64"
            case canonicalPayloadB64 = "canonical_payload_b64"
            case transactionIDB64 = "transaction_id_b64"
            case deviceKeyGeneration = "device_key_generation"
            case delegationSerial = "delegation_serial"
            case delegationExpiresAt = "delegation_expires_at"
        }

        init(from decoder: any Decoder) throws {
            let dynamic = try decoder.container(keyedBy: LeafDynamicKey.self)
            guard Set(dynamic.allKeys.map(\.stringValue)) == Set(CodingKeys.allCases.map(\.rawValue))
            else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unexpected PXLA fields")) }
            let value = try decoder.container(keyedBy: CodingKeys.self)
            schema = try value.decode(String.self, forKey: .schema)
            correlationIDB64 = try value.decode(String.self, forKey: .correlationIDB64)
            canonicalPayloadB64 = try value.decode(String.self, forKey: .canonicalPayloadB64)
            transactionIDB64 = try value.decode(String.self, forKey: .transactionIDB64)
            deviceKeyGeneration = try value.decode(UInt64.self, forKey: .deviceKeyGeneration)
            delegationSerial = try value.decode(String.self, forKey: .delegationSerial)
            delegationExpiresAt = try value.decode(UInt64.self, forKey: .delegationExpiresAt)
            purpose = try value.decode(String.self, forKey: .purpose)
        }
    }

    private struct PXLA {
        let siteUUID: Data
        let transactionID: Data
        let deviceKeyGeneration: UInt64
        let issuedAt: UInt64
        let expiresAt: UInt64

        init(_ data: Data) throws {
            guard data.count >= 8, data.prefix(7) == Data("PXLA/v1".utf8), data[7] == 1 else {
                throw PlatformFailure.siteRootAuthorityUnavailable
            }
            var cursor = 8
            var fields: [Data] = []
            for expectedTag in UInt8(1) ... UInt8(26) {
                guard cursor + 3 <= data.count, data[cursor] == expectedTag else {
                    throw PlatformFailure.siteRootAuthorityUnavailable
                }
                let count = Int(data[cursor + 1]) << 8 | Int(data[cursor + 2])
                cursor += 3
                guard count > 0, cursor + count <= data.count else {
                    throw PlatformFailure.siteRootAuthorityUnavailable
                }
                fields.append(Data(data[cursor ..< cursor + count]))
                cursor += count
            }
            let digestFieldsValid = [9, 10, 11, 15, 17, 18, 19, 23, 24, 25]
                .allSatisfy { index in
                    fields[index].count == 32 && !fields[index].allSatisfy({ $0 == 0 })
                }
            guard let dasNotBefore = Self.u64(fields[13]),
                  let dasNotAfter = Self.u64(fields[14]),
                  let monasNotBefore = Self.u64(fields[21]),
                  let monasNotAfter = Self.u64(fields[22]),
                  cursor == data.count,
                  fields[0].count == 16, !fields[0].allSatisfy({ $0 == 0 }),
                  Self.identifier(fields[1]), Self.identifier(fields[2]),
                  String(data: fields[1], encoding: .utf8)?.hasPrefix("x509-root-") == true,
                  String(data: fields[2], encoding: .utf8)?.hasPrefix("x509-issuing-") == true,
                  fields[3].count == 16, !fields[3].allSatisfy({ $0 == 0 }),
                  let issued = Self.u64(fields[4]), let expires = Self.u64(fields[5]),
                  expires > issued, expires - issued <= 300,
                  fields[6].count == 32, !fields[6].allSatisfy({ $0 == 0 }),
                  let generation = Self.u64(fields[7]), generation > 0,
                  String(data: fields[8], encoding: .utf8) == "service-dasobjectstore-s3",
                  String(data: fields[16], encoding: .utf8) == "service-monas-web",
                  digestFieldsValid,
                  fields[12].count == 16, !fields[12].allSatisfy({ $0 == 0 }),
                  fields[20].count == 16, !fields[20].allSatisfy({ $0 == 0 }),
                  dasNotAfter > dasNotBefore,
                  monasNotAfter > monasNotBefore
            else { throw PlatformFailure.siteRootAuthorityUnavailable }
            siteUUID = fields[0]
            transactionID = fields[3]
            deviceKeyGeneration = generation
            issuedAt = issued
            expiresAt = expires
        }

        private static func identifier(_ value: Data) -> Bool {
            guard let string = String(data: value, encoding: .utf8) else { return false }
            return SiteX509LeafApprovalPresentationV1.identifier(string)
        }

        private static func u64(_ value: Data) -> UInt64? {
            guard value.count == 8 else { return nil }
            return value.reduce(0) { ($0 << 8) | UInt64($1) }
        }
    }

    private static func identifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                || ($0 >= 97 && $0 <= 122) || [45, 46, 58, 95].contains($0)
        }
    }

    private static func standardBase64(_ value: String, count: Int) -> Data? {
        guard let data = standardBase64(value, range: count ... count) else { return nil }
        return data
    }

    private static func standardBase64(_ value: String, range: ClosedRange<Int>) -> Data? {
        guard !value.isEmpty, value.count % 4 == 0,
              !value.contains("-"), !value.contains("_"),
              let data = Data(base64Encoded: value), range.contains(data.count),
              data.base64EncodedString() == value else { return nil }
        return data
    }

    private static func uuid(_ value: String) -> Data? {
        let hex = value.replacingOccurrences(of: "-", with: "").lowercased()
        guard hex.count == 32, hex.allSatisfy({ $0.isHexDigit }) else { return nil }
        var bytes = Data(capacity: 16)
        var index = hex.startIndex
        for _ in 0 ..< 16 {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index ..< next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return bytes
    }
}

struct SiteX509LeafApprovalSubmissionV1: Encodable, Sendable {
    let schema = SiteX509LeafApprovalProfileV1.submitSchema
    let correlationIDB64: String
    let canonicalPayloadB64: String
    let transactionIDB64: String
    let deviceKeyGeneration: UInt64
    let delegationSerial: String
    let delegationExpiresAt: UInt64
    let detachedCOSESign1B64: String

    enum CodingKeys: String, CodingKey {
        case schema
        case correlationIDB64 = "correlation_id_b64"
        case canonicalPayloadB64 = "canonical_payload_b64"
        case transactionIDB64 = "transaction_id_b64"
        case deviceKeyGeneration = "device_key_generation"
        case delegationSerial = "delegation_serial"
        case delegationExpiresAt = "delegation_expires_at"
        case detachedCOSESign1B64 = "detached_cose_sign1_b64"
    }
}

struct SiteX509LeafApprovalAcceptedV1: Sendable {
    init(data: Data, expected: SiteX509LeafApprovalPresentationV1) throws {
        let value: Wire
        do { value = try JSONDecoder().decode(Wire.self, from: data) }
        catch { throw PlatformFailure.siteRootAuthorityUnavailable }
        guard value.schema == SiteX509LeafApprovalProfileV1.acceptedSchema,
              value.status == "accepted",
              Data(base64Encoded: value.correlationIDB64) == expected.correlationID,
              value.correlationIDB64 == expected.correlationID.base64EncodedString(),
              Data(base64Encoded: value.transactionIDB64) == expected.transactionID,
              value.transactionIDB64 == expected.transactionID.base64EncodedString()
        else { throw PlatformFailure.siteRootAuthorityUnavailable }
    }

    private struct Wire: Decodable {
        let schema: String
        let correlationIDB64: String
        let transactionIDB64: String
        let status: String

        enum CodingKeys: String, CodingKey, CaseIterable {
            case schema, status
            case correlationIDB64 = "correlation_id_b64"
            case transactionIDB64 = "transaction_id_b64"
        }

        init(from decoder: any Decoder) throws {
            let dynamic = try decoder.container(keyedBy: LeafDynamicKey.self)
            guard Set(dynamic.allKeys.map(\.stringValue)) == Set(CodingKeys.allCases.map(\.rawValue))
            else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unexpected PXLA acceptance fields")) }
            let value = try decoder.container(keyedBy: CodingKeys.self)
            schema = try value.decode(String.self, forKey: .schema)
            correlationIDB64 = try value.decode(String.self, forKey: .correlationIDB64)
            transactionIDB64 = try value.decode(String.self, forKey: .transactionIDB64)
            status = try value.decode(String.self, forKey: .status)
        }
    }
}

final class SecureEnclaveSiteX509LeafApprovalProducerV1: @unchecked Sendable {
    private let store: SiteRootConvergenceAckStoreV2

    init(store: SiteRootConvergenceAckStoreV2 = SiteRootConvergenceAckStoreV2()) {
        self.store = store
    }

    func produce(
        _ presentation: SiteX509LeafApprovalPresentationV1
    ) async throws -> SiteX509LeafApprovalSubmissionV1 {
        let ceremony = try await FaceIDCeremonyContext.authenticate(
            reason: "Approve the first DASObjectStore and Monas HTTPS certificates"
        )
        return try produce(presentation, using: ceremony)
    }

    func produce(
        _ presentation: SiteX509LeafApprovalPresentationV1,
        using ceremony: FaceIDCeremonyContext
    ) throws -> SiteX509LeafApprovalSubmissionV1 {
        let record = try store.current()
        try presentation.validateCurrentSigner(record)
        let signer = try SecureEnclaveSigner(
            namespace: "site-root-convergence-ack-v2",
            authenticationReason: "Approve the first DASObjectStore and Monas HTTPS certificates"
        )
        guard try signer.hasExistingKey() else { throw PlatformFailure.keyNotFound }
        let protected = try DetachedES256Cose.protectedHeaders(
            kid: presentation.deviceKeyGeneration.bigEndianData,
            contentType: SiteX509LeafApprovalProfileV1.contentType
        )
        let structure = try DetachedES256Cose.signatureStructure(
            protected: protected, payload: presentation.canonicalPayload
        )
        let signature = try signer.sign(message: structure, using: ceremony)
        let cose = try DetachedES256Cose.envelope(protected: protected, signature: signature)
        return SiteX509LeafApprovalSubmissionV1(
            correlationIDB64: presentation.correlationID.base64EncodedString(),
            canonicalPayloadB64: presentation.canonicalPayload.base64EncodedString(),
            transactionIDB64: presentation.transactionID.base64EncodedString(),
            deviceKeyGeneration: presentation.deviceKeyGeneration,
            delegationSerial: presentation.delegationSerial,
            delegationExpiresAt: presentation.delegationExpiresAt,
            detachedCOSESign1B64: cose.base64EncodedString()
        )
    }
}

private struct LeafDynamicKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}

private extension FixedWidthInteger {
    var bigEndianData: Data { withUnsafeBytes(of: bigEndian) { Data($0) } }
}
