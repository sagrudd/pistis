import Foundation

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

/// Reference-only detached signature output. It must never be described as COSE
/// or as production mobile interoperability.
struct ReferenceDetachedSignature: Equatable, Sendable {
    let canonicalPayload: Data
    let rawES256Signature: Data
}
