import CryptoKit
import Darwin
import Foundation

/// Shape and attended-payload checks only. The wrapper and endpoint remain
/// provisional until the signed proof and operation-bound native response.
struct SiteX509LeafHandoffV2 {
    let presentation: SiteX509LeafApprovalPresentationV1
    let nativeOrigin: URL

    init(data: Data, operationID: Data, correlationDigest: Data,
         expectedSiteUUID: Data, nowUnixSeconds: UInt64) throws {
        let object = try StrictJSONObject(data: data, maximumBytes: 8_192).values
        guard Set(object.keys) == ["schema", "operation_id_b64url", "correlation_digest_b64url",
                                   "ordered_ip_octets_b64url", "native_origin", "presentation"],
              object["schema"] == .string("monas.first-device.leaf-handoff.v2"),
              operationID.count == 16, !operationID.allSatisfy({ $0 == 0 }),
              correlationDigest.count == 32, !correlationDigest.allSatisfy({ $0 == 0 }),
              object["operation_id_b64url"] == .string(SiteRootBrokerPresentationV2.encode(operationID)),
              object["correlation_digest_b64url"] == .string(SiteRootBrokerPresentationV2.encode(correlationDigest)),
              case let .array(addresses)? = object["ordered_ip_octets_b64url"], (1...16).contains(addresses.count),
              case let .string(origin)? = object["native_origin"],
              case .object? = object["presentation"],
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let nested = json["presentation"]
        else { throw PlatformFailure.invalidConfiguration }
        let nestedData = try JSONSerialization.data(withJSONObject: nested)
        let parsed = try SiteX509LeafApprovalPresentationV1(data: nestedData, nowUnixSeconds: nowUnixSeconds)
        guard parsed.siteUUID == expectedSiteUUID else { throw PlatformFailure.invalidConfiguration }
        var previous: Data?, hashInput = Data(), origins = Set<String>()
        for item in addresses {
            guard case let .string(encoded) = item,
                  let bytes = SiteRootBrokerPresentationV2.base64(encoded, maximum: 16),
                  bytes.count == 4 || bytes.count == 16,
                  Self.isPrivate(bytes) else { throw PlatformFailure.invalidConfiguration }
            if let previous {
                let ordered = previous.count == bytes.count
                    ? previous.lexicographicallyPrecedes(bytes) : previous.count < bytes.count
                guard ordered else { throw PlatformFailure.invalidConfiguration }
            }
            previous = bytes
            hashInput.append(UInt8(bytes.count)); hashInput.append(bytes)
            let family = bytes.count == 4 ? AF_INET : AF_INET6
            var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let capacity = socklen_t(INET6_ADDRSTRLEN)
            let rendered = bytes.withUnsafeBytes { raw in
                inet_ntop(family, raw.baseAddress, &text, capacity)
            }
            guard rendered != nil else { throw PlatformFailure.invalidConfiguration }
            let ip = String(cString: text)
            origins.insert(bytes.count == 4 ? "https://\(ip):8443" : "https://[\(ip)]:8443")
        }
        guard Data(SHA256.hash(data: hashInput)) == parsed.monasIPSetSHA256,
              origins.contains(origin), let url = URL(string: origin)
        else { throw PlatformFailure.invalidConfiguration }
        presentation = parsed
        nativeOrigin = url
    }

    private static func isPrivate(_ value: Data) -> Bool {
        let b = [UInt8](value)
        if b.count == 16 { return b[0] & 0xfe == 0xfc }
        guard b.count == 4 else { return false }
        return b[0] == 10 || (b[0] == 172 && (16...31).contains(b[1])) || (b[0] == 192 && b[1] == 168)
    }
}
