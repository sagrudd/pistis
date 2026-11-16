import CryptoKit
import Foundation

/// Closed response matching; authority requires the separately pinned native
/// channel established from the attended leaf handoff.
struct BrokerCustodyChallengeV2 {
    let challenge: CustodyRotationAppAttestChallengeV2

    init(data: Data, pending: ScopedAppAttestPending, nowUnixSeconds: UInt64) throws {
        try pending.validate()
        var uuid = pending.attemptID.uuid
        let operation = withUnsafeBytes(of: &uuid) { Data($0) }
        let correlation = Data(SHA256.hash(data:
            Data("mnemosyne.monas.first-device.correlation.v2\0".utf8) + pending.correlation))
        let object = try StrictJSONObject(data: data, maximumBytes: 12 * 1024).values
        guard Set(object.keys) == ["schema", "operation_id_b64url", "correlation_digest_b64url", "challenge"],
              object["schema"] == .string("monas.first-device.custody-challenge.v2"),
              object["operation_id_b64url"] == .string(SiteRootBrokerPresentationV2.encode(operation)),
              object["correlation_digest_b64url"] == .string(SiteRootBrokerPresentationV2.encode(correlation)),
              case .object? = object["challenge"],
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let nested = json["challenge"],
              let key = PendingAppAttestReplacementKeyV1.canonicalKeyID(pending.keyID)
        else { throw PlatformFailure.invalidConfiguration }
        let inner = try CustodyRotationAppAttestChallengeV2(
            data: JSONSerialization.data(withJSONObject: nested), nowUnixSeconds: nowUnixSeconds)
        guard inner.siteTrustDomain == pending.siteClaim, inner.appIdentifier == pending.appClaim,
              inner.keyID == key, pending.environmentClaim == "Production"
        else { throw PlatformFailure.appAttestInvalidInput }
        challenge = inner
    }
}
