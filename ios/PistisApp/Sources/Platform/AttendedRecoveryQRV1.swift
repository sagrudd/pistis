#if DEBUG
import CryptoKit
import Foundation

/// Test-only decoder. Its claims remain provisional until the attended pairing
/// and host verification complete; it cannot activate an installation.
struct AttendedRecoveryQRV1 {
    let requestID: Data
    let relaySecret: Data
    let intentDigest: Data
    let transcript: AttendedRecoveryTranscriptV1
    let pending: ScopedAppAttestPending

    init(data: Data, now: UInt64, storage: ScopedAppAttestStore) throws {
        let object = try StrictJSONObject(data: data, maximumBytes: 4_096).values
        guard Set(object.keys) == ["schema", "intent_b64url", "phone_relay_secret_b64url", "reference",
                                   "site", "app_attest_key_id_b64url", "site_root_public_key_b64url"],
              case .string("mnemosyne.monas.attended-recovery.qr.v1")? = object["schema"],
              case let .string(intentText)? = object["intent_b64url"],
              let intent = SiteRootBrokerPresentationV2.base64(intentText, exact: 428),
              case let .string(relayText)? = object["phone_relay_secret_b64url"],
              let relay = SiteRootBrokerPresentationV2.base64(relayText, exact: 32),
              case let .string(reference)? = object["reference"],
              case let .string(site)? = object["site"],
              case let .string(keyText)? = object["app_attest_key_id_b64url"],
              let key = SiteRootBrokerPresentationV2.base64(keyText, exact: 32),
              case let .string(rootText)? = object["site_root_public_key_b64url"],
              let root = SiteRootBrokerPresentationV2.base64(rootText, exact: 33)
        else { throw PlatformFailure.qrPayloadUnsupported }
        let prefix = Data("mnemosyne.monas.attended-recovery.intent.v1\0".utf8)
        guard intent.starts(with: prefix) else { throw PlatformFailure.qrPayloadUnsupported }
        var offset = prefix.count
        func take(_ count: Int) -> Data {
            defer { offset += count }
            return intent.subdata(in: offset..<(offset + count))
        }
        let registration = take(32), operation = take(16), correlationDigest = take(32)
        let installation = take(16), siteDigest = take(32), owner = take(16), result = take(32)
        let request = take(16), activation = take(16), nonce = take(32), relayDigest = take(32)
        let pollDigest = take(32), verifierDigest = take(32), endpoint = take(32)
        let mailboxExpiry = take(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let successorExpiry = take(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let fixed = [registration, operation, correlationDigest, installation, siteDigest, owner, result,
                     request, activation, nonce, relayDigest, pollDigest, verifierDigest, endpoint]
        let endpoints = ["https://install.mnemosyne.co.uk",
            "/api/first-install/v1/attended-recovery/rendezvous",
            "/api/first-install/v1/attended-recovery/proofs",
            "/api/first-install/v1/attended-recovery/proof-polls",
            "/api/first-install/v1/attended-recovery/activations",
            "/api/first-install/v1/attended-recovery/activation-status"]
        let expectedEndpoint = Data(SHA256.hash(data: Data(
            ("mnemosyne.monas.attended-recovery.endpoints.v1\0" + endpoints.joined(separator: "\0")).utf8)))
        guard offset == intent.count, fixed.allSatisfy({ !$0.allSatisfy({ $0 == 0 }) }),
              endpoint == expectedEndpoint, relayDigest != pollDigest,
              Data(SHA256.hash(data: relay)) == relayDigest,
              Data(SHA256.hash(data: Data(site.utf8))) == siteDigest,
              mailboxExpiry <= UInt64(UInt32.max), successorExpiry <= UInt64(UInt32.max),
              mailboxExpiry > now, mailboxExpiry - now <= 120,
              successorExpiry > mailboxExpiry, successorExpiry - now <= 900
        else { throw PlatformFailure.qrPayloadUnsupported }
        let op = [UInt8](operation)
        let id = UUID(uuid: (op[0],op[1],op[2],op[3],op[4],op[5],op[6],op[7],op[8],op[9],op[10],op[11],op[12],op[13],op[14],op[15]))
        guard let submitted = try storage.submittedAttempt(attemptID: id),
              let pending = try storage.pending(attemptID: id),
              let pendingKey = PendingAppAttestReplacementKeyV1.canonicalKeyID(submitted.keyID),
              pendingKey == key, pending.appClaim == AppleAppAttestRegistrationEnvelope.reviewedAppIdentifier,
              pending.environmentClaim == "Production",
              Data(SHA256.hash(data: Data("mnemosyne.monas.first-device.correlation.v2\0".utf8) + pending.correlation)) == correlationDigest
        else { throw PlatformFailure.qrPayloadUnsupported }
        let value = AttendedRecoveryTranscriptV1(nonce: nonce, operation: operation, correlation: pending.correlation,
            reference: reference, site: site, installation: installation, appAttestKeyID: key,
            siteRootPublicKey: root, ownerTransaction: owner, ownerResult: result,
            endpointCommitment: endpoint, rendezvousCommitment: Data(SHA256.hash(data: intent)), expiry: mailboxExpiry)
        guard submitted.matchesRecovery(value) else { throw PlatformFailure.qrPayloadUnsupported }
        _ = try value.bytes()
        requestID = request; relaySecret = relay; intentDigest = Data(SHA256.hash(data: intent))
        transcript = value; self.pending = pending
    }
}
#endif
