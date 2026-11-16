import Foundation
import CryptoKit

/// Broker-only V2 transcript. Input must come from a strictly validated V2
/// presentation and the durable pending attempt; this value does not itself
/// authenticate either one and is never a transport or authority selection.
enum SiteRootBrokerRegistrationTranscriptV2 {
    static func clientDataHash(
        operationID: Data, correlation: Data, reference: String, hostChallenge: Data
    ) throws -> Data {
        guard operationID.count == 16, !operationID.allSatisfy({ $0 == 0 }),
              correlation.count == 32, !correlation.allSatisfy({ $0 == 0 }),
              hostChallenge.count == 32, !hostChallenge.allSatisfy({ $0 == 0 }),
              !reference.isEmpty, reference.utf8.count <= 128,
              reference.utf8.allSatisfy({
                  (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
                      || [45, 46, 58, 95].contains($0)
              }) else { throw PlatformFailure.appAttestInvalidInput }
        let correlationHash = Data(SHA256.hash(
            data: Data("mnemosyne.monas.first-device.correlation.v2\0".utf8) + correlation
        ))
        let referenceHash = Data(SHA256.hash(data: Data(reference.utf8)))
        return Data(SHA256.hash(
            data: Data("mnemosyne.monas.first-device.registration.v2\0".utf8)
                + operationID + correlationHash + referenceHash + hostChallenge
        ))
    }
}
