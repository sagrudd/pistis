import CryptoKit
import Foundation

enum SiteRootAcknowledgementStage: Equatable, Sendable {
    case preparing
    case awaitingFaceID
    case signing
    case waitingForMonas
}

enum SiteRootAcknowledgementFailure: Error {
    case registrationUnavailable
    case transport
    case http(Int)
    case invalidResponse

    var supportCode: String {
        switch self {
        case .registrationUnavailable: "ACK-REGISTRATION-UNAVAILABLE"
        case .transport: "ACK-CONNECTION-FAILED"
        case let .http(status): "ACK-HTTP-\(status)"
        case .invalidResponse: "ACK-RESPONSE-INVALID"
        }
    }
}

/// Existing protected registration continuity, not a new registration authority.
enum RetainedSiteRootAcknowledgementV2 {
    static func submit(
        _ presentation: SiteRootConvergenceAckPresentationV2,
        record: SiteRootConvergenceAckRecordV2?,
        siteRootPublic: Data,
        ackPublic: Data,
        nowMilliseconds: UInt64,
        sign: (Data) throws -> Data,
        progress: @MainActor @Sendable (SiteRootAcknowledgementStage) -> Void = { _ in },
        send: (Data, URL) async throws -> Void
    ) async throws {
        try Task.checkCancellation()
        guard let record else { throw PlatformFailure.invalidConfiguration }
        let assertion = try UnsignedSiteRootConvergenceAssertionV2(
            presentation.unsignedPXRA, nowUnixMilliseconds: nowMilliseconds
        )
        let signerID = Data(SHA256.hash(data: siteRootPublic))
        guard siteRootPublic.count == 33, ackPublic.count == 33,
              (try? P256.Signing.PublicKey(compressedRepresentation: siteRootPublic)) != nil,
              (try? P256.Signing.PublicKey(compressedRepresentation: ackPublic)) != nil,
              record.siteUUID == assertion.siteUUIDText,
              record.targetIDB64URL == SiteRootConvergenceEncoding.encode(signerID),
              record.ackPublicKeyB64URL == SiteRootConvergenceEncoding.encode(ackPublic),
              record.generation > 0, record.generation == assertion.ackKeyGeneration
        else { throw PlatformFailure.invalidConfiguration }
        // PXRA names the native target, not signerID. Sign its original bytes.
        let headers = try DetachedES256Cose.protectedHeaders(
            kid: SiteRootConvergenceEncoding.uint64Bytes(record.generation),
            contentType: SiteRootConvergenceProfileV2.pxraContentType
        )
        let structure = try DetachedES256Cose.signatureStructure(
            protected: headers, payload: presentation.unsignedPXRA
        )
        let signature = try sign(structure)
        let proof = try DetachedES256Cose.envelope(protected: headers, signature: signature)
        let signed = presentation.unsignedPXRA + proof
        guard signed.count <= 768 else { throw PlatformFailure.invalidConfiguration }
        await progress(.waitingForMonas)
        try Task.checkCancellation()
        try await send(signed, presentation.submissionURL)
    }
}
