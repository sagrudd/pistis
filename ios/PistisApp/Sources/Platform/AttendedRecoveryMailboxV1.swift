#if DEBUG
import Foundation
import CryptoKit

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
/// Provisional, test-only successor phase envelopes. No transport is started.
enum AttendedRecoveryPhaseWireV1 {
    enum Phase: String { case rootUnlock = "root-unlock", issuerUnlock = "issuer-unlock", ackRegistration = "ack-registration", leafApproval = "leaf-approval" }
    enum PollResult: Equatable { case pending, submitted, accepted, ready(Data) }
    private static let origin = "https://install.mnemosyne.co.uk/api/first-install/v1/attended-recovery/"
    static let pollEndpoint = URL(string: origin + "presentations")!
    static let submitEndpoint = URL(string: origin + "submissions")!
    private static let responseSchema = "mnemosyne.monas.first-install-broker.response.v1"

    static func poll(requestID: Data, capability: Data, phase: Phase) throws -> URLRequest {
        try request(endpoint: pollEndpoint, schema: "mnemosyne.monas.first-install-broker.attended-presentation-poll.v1", requestID: requestID, capability: capability, phase: phase, extra: [:])
    }
    static func submit(requestID: Data, capability: Data, phase: Phase, presentationDigest: Data, submission: Data) throws -> URLRequest {
        guard presentationDigest.count == 32, !presentationDigest.allSatisfy({ $0 == 0 }), !submission.isEmpty, submission.count <= 16_384 else { throw PlatformFailure.invalidConfiguration }
        return try request(endpoint: submitEndpoint, schema: "mnemosyne.monas.first-install-broker.attended-submission.v1", requestID: requestID, capability: capability, phase: phase, extra: ["presentation_sha256_b64url": SiteRootBrokerPresentationV2.encode(presentationDigest), "submission_b64url": SiteRootBrokerPresentationV2.encode(submission)])
    }
    private static func request(endpoint: URL, schema: String, requestID: Data, capability: Data, phase: Phase, extra: [String: String]) throws -> URLRequest {
        guard requestID.count == 16, capability.count == 32, !requestID.allSatisfy({ $0 == 0 }), !capability.allSatisfy({ $0 == 0 }) else { throw PlatformFailure.invalidConfiguration }
        var object = extra
        object["schema"] = schema; object["request_id_b64url"] = SiteRootBrokerPresentationV2.encode(requestID)
        object["phone_capability_b64url"] = SiteRootBrokerPresentationV2.encode(capability); object["phase"] = phase.rawValue
        let body = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard body.count <= 32_768 else { throw PlatformFailure.invalidConfiguration }
        var value = URLRequest(url: endpoint); value.httpMethod = "POST"; value.httpBody = body
        value.setValue("application/json", forHTTPHeaderField: "Content-Type"); value.setValue("application/json", forHTTPHeaderField: "Accept")
        value.setValue("no-store", forHTTPHeaderField: "Cache-Control"); value.timeoutInterval = 15
        return value
    }
    static func pollResponse(_ data: Data, response: HTTPURLResponse) throws -> PollResult {
        try validateHeaders(response, endpoint: pollEndpoint, status: 200)
        let fields = try StrictJSONObject(data: data, maximumBytes: 32_768, maximumStringBytes: 24_000).values
        guard fields["schema"] == .string(responseSchema), case let .string(state)? = fields["state"] else { throw PlatformFailure.invalidConfiguration }
        let common: [String: StrictJSONObject.Value] = ["schema": .string(responseSchema), "state": .string(state)]
        switch state {
        case "pending": guard fields == common else { throw PlatformFailure.invalidConfiguration }; return .pending
        case "submitted": guard fields == common else { throw PlatformFailure.invalidConfiguration }; return .submitted
        case "accepted": guard fields == common else { throw PlatformFailure.invalidConfiguration }; return .accepted
        case "ready":
            guard fields.count == 4, case let .string(encoded)? = fields["presentation_b64url"],
                  case let .string(digestText)? = fields["presentation_sha256_b64url"],
                  let presentation = SiteRootBrokerPresentationV2.base64(encoded, maximum: 16_384, requireNonzero: false),
                  let digest = SiteRootBrokerPresentationV2.base64(digestText, exact: 32),
                  Data(SHA256.hash(data: presentation)) == digest else { throw PlatformFailure.invalidConfiguration }
            return .ready(presentation)
        default: throw PlatformFailure.invalidConfiguration
        }
    }
    static func submissionReceipt(_ data: Data, response: HTTPURLResponse) throws {
        try validateHeaders(response, endpoint: submitEndpoint, status: 202)
        guard try StrictJSONObject(data: data, maximumBytes: 4_096).values == ["schema": .string(responseSchema), "state": .string("submitted")] else { throw PlatformFailure.invalidConfiguration }
    }
    private static func validateHeaders(_ response: HTTPURLResponse, endpoint: URL, status: Int) throws {
        guard response.url == endpoint, response.statusCode == status,
              ["application/json", "application/json; charset=utf-8"].contains(response.value(forHTTPHeaderField: "Content-Type")?.lowercased() ?? ""),
              response.value(forHTTPHeaderField: "Cache-Control")?.split(separator: ",").contains(where: { $0.trimmingCharacters(in: .whitespaces).lowercased() == "no-store" }) == true,
              response.value(forHTTPHeaderField: "Set-Cookie") == nil else { throw PlatformFailure.invalidConfiguration }
    }
}
#endif
