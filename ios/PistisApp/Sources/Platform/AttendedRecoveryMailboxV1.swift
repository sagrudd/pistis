#if DEBUG
import Foundation

/// Test-only envelope. A broker receipt is not host acceptance.
enum AttendedRecoveryMailboxV1 {
    static let endpoint = URL(string: "https://install.mnemosyne.co.uk/api/first-install/v1/attended-recovery/proofs")!
    private static let schema = "mnemosyne.monas.first-install-broker.attended-proof.v1"
    private static let responseSchema = "mnemosyne.monas.first-install-broker.response.v1"

    static func request(requestID: Data, relaySecret: Data, intentDigest: Data, proof: Data) throws -> URLRequest {
        let values = [(requestID, 16), (relaySecret, 32), (intentDigest, 32)]
        guard values.allSatisfy({ $0.0.count == $0.1 && !$0.0.allSatisfy({ $0 == 0 }) }),
              !proof.isEmpty, proof.count <= 8_192 else { throw PlatformFailure.invalidConfiguration }
        let encode = SiteRootBrokerPresentationV2.encode
        let body = try JSONSerialization.data(withJSONObject: ["schema": schema,
            "request_id_b64url": encode(requestID), "phone_relay_secret_b64url": encode(relaySecret),
            "intent_sha256_b64url": encode(intentDigest), "proof_b64url": encode(proof)], options: [.sortedKeys])
        guard body.count <= 32_768 else { throw PlatformFailure.invalidConfiguration }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"; request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.timeoutInterval = 15
        return request
    }

    static func validateReceipt(_ data: Data, response: HTTPURLResponse) throws {
        guard response.url == endpoint, response.statusCode == 200,
              ["application/json", "application/json; charset=utf-8"].contains(
                response.value(forHTTPHeaderField: "Content-Type")?.lowercased() ?? ""),
              response.value(forHTTPHeaderField: "Cache-Control")?.split(separator: ",").contains(where: {
                $0.trimmingCharacters(in: .whitespaces).lowercased() == "no-store"
              }) == true,
              response.value(forHTTPHeaderField: "Set-Cookie") == nil,
              try StrictJSONObject(data: data, maximumBytes: 4_096).values == [
                "schema": .string(responseSchema), "state": .string("accepted")
              ] else { throw PlatformFailure.invalidConfiguration }
    }
}
#endif
