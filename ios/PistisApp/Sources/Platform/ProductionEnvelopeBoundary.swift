import Foundation
import PistisCore

/// Protocol signing boundary kept explicit until reviewed COSE fixtures exist.
protocol ProductionEnvelopeProducing: Sendable {
    func produceEnvelope(canonicalPayload: Data) async throws -> Data
}

/// Fail-closed implementation used while ADR 0006's COSE prerequisite remains open.
struct UnsupportedProductionEnvelope: ProductionEnvelopeProducing {
    func produceEnvelope(canonicalPayload _: Data) async throws -> Data {
        throw PlatformFailure.productionEnvelopeUnavailable
    }
}

/// Accepted ADR 0018 envelope production backed only by the enrolled Secure
/// Enclave key. Both approval and denial pass through this same Face ID gate.
struct SecureEnclaveProductionEnvelope: ProductionEnvelopeProducing {
    let signer: SecureEnclaveSigner
    let deviceKeyID: Data

    init(signer: SecureEnclaveSigner, deviceKeyID: Data) throws {
        guard deviceKeyID.count == 32 else { throw PlatformFailure.invalidConfiguration }
        self.signer = signer
        self.deviceKeyID = deviceKeyID
    }

    func produceEnvelope(canonicalPayload: Data) async throws -> Data {
        let structure = try CoseSign1.signatureStructure(
            keyID: deviceKeyID,
            payload: canonicalPayload
        )
        let signature = try signer.sign(message: structure)
        return try CoseSign1(
            keyID: deviceKeyID,
            payload: canonicalPayload,
            signature: signature
        ).encoded()
    }
}

/// Reference-only detached signature output. It must never be described as COSE
/// or as production mobile interoperability.
struct ReferenceDetachedSignature: Equatable, Sendable {
    let canonicalPayload: Data
    let rawES256Signature: Data
}
