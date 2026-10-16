import Foundation

/// Public correlation and detached-proof carriage only. These codecs cannot
/// authenticate a native session, establish current owners or consume an act.
public enum NativeInstallApprovalWire {
    public struct Plan: Sendable {
        public let operationID: Data
        public let requestDigest: Data
        public let expectationDigest: Data
        public let queryDigest: Data
        public let sourceFingerprint: Data
        public init(canonicalBytes: Data) throws {
            let f = try IssuerCBOR.decode(canonicalBytes, maximum: 512).array(7)
            guard f[0] == .unsigned(1), try f[1].bytes() == Data("issuer-native-purpose-prepare-v1".utf8) else { throw IssuerPhoneError.binding }
            operationID = try f[2].bytes(16, nonzero: true)
            requestDigest = try f[3].bytes(32, nonzero: true)
            expectationDigest = try f[4].bytes(32, nonzero: true)
            queryDigest = try f[5].bytes(32, nonzero: true)
            sourceFingerprint = try f[6].bytes(32, nonzero: true)
        }
    }
    public static let preparePath = "/auth/pistis/v2/issuer/native-purpose/prepare"
    public static let submitPath = "/auth/pistis/v2/issuer/native-purpose/submit"

    public static func prepare(plan: Plan, phoneNonce: Data) throws -> Data {
        try prepare(operationID: plan.operationID, requestDigest: plan.requestDigest,
            expectationDigest: plan.expectationDigest, queryDigest: plan.queryDigest,
            sourceFingerprint: plan.sourceFingerprint, phoneNonce: phoneNonce)
    }
    public static func accepted(_ raw: Data, task: NativeInstallApprovalTask, phoneNonce: Data) throws {
        guard phoneNonce.count == 32, !phoneNonce.allSatisfy({ $0 == 0 }) else { throw IssuerPhoneError.binding }
        let f = try IssuerCBOR.decode(raw, maximum: 512).array(6)
        guard f[0] == .unsigned(1), f[1] == .unsigned(8),
              try f[2].bytes(16) == task.taskID, try f[3].bytes(32) == task.bodyDigest,
              try f[4].bytes(32) == phoneNonce,
              try f[5].bytes() == Data("accepted-native-purpose-v1".utf8) else { throw IssuerPhoneError.binding }
    }
    public static func prepare(operationID: Data, requestDigest: Data,
                               expectationDigest: Data, queryDigest: Data,
                               sourceFingerprint: Data, phoneNonce: Data) throws -> Data {
        guard operationID.count == 16, !operationID.allSatisfy({ $0 == 0 }),
              [requestDigest, expectationDigest, queryDigest, sourceFingerprint, phoneNonce].allSatisfy({ $0.count == 32 && !$0.allSatisfy({ $0 == 0 }) }) else { throw IssuerPhoneError.binding }
        return try IssuerCBOR.array([.unsigned(1), .bytes(Data("issuer-native-purpose-prepare-v1".utf8)),
            .bytes(operationID), .bytes(requestDigest), .bytes(expectationDigest), .bytes(queryDigest),
            .bytes(sourceFingerprint), .bytes(phoneNonce)]).encoded(maximum: 512)
    }
    public static func submission(task: NativeInstallApprovalTask, phoneNonce: Data,
                                  detachedACKProof: Data) throws -> Data {
        guard phoneNonce.count == 32, !phoneNonce.allSatisfy({ $0 == 0 }),
              detachedACKProof.count == 83 else { throw IssuerPhoneError.binding }
        // phoneNonce echoes the phone's prepare request. BODY10[3] is a
        // different server nonce and remains covered by the ACK signature.
        return try IssuerCBOR.array([.unsigned(1), .unsigned(8), .bytes(task.taskID),
            .bytes(task.bodyDigest), .bytes(phoneNonce), .bytes(detachedACKProof)]).encoded(maximum: 12_288)
    }
}
