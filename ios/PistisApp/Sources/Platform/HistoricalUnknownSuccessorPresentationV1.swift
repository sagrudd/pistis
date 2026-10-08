import Foundation

/// Local, non-authorising projection of a proposed historical-unknown successor.
/// This is not a wire schema and must not be used by ADR-0042 or ADR-0025 routes.
struct HistoricalUnknownSuccessorPresentationV1: Equatable, Sendable {
    let site: String
    let vaultIdentity: String
    let consumedGeneration: UInt64
    let proposedGeneration: UInt64
    let freshHostKeyDigest: String
    let purposeClaim: String
    let requestIDClaim: String
    let contractRevisionClaim: String

    init?(
        site: String,
        vaultIdentity: String,
        consumedGeneration: UInt64,
        proposedGeneration: UInt64,
        freshHostKeyDigest: String,
        purposeClaim: String,
        requestIDClaim: String,
        contractRevisionClaim: String
    ) {
        guard !site.isEmpty,
              !vaultIdentity.isEmpty,
              consumedGeneration > 0,
              consumedGeneration < UInt64.max,
              proposedGeneration == consumedGeneration + 1,
              Self.isCanonicalSHA256Digest(freshHostKeyDigest),
              !purposeClaim.isEmpty,
              !requestIDClaim.isEmpty,
              !contractRevisionClaim.isEmpty
        else { return nil }

        self.site = site
        self.vaultIdentity = vaultIdentity
        self.consumedGeneration = consumedGeneration
        self.proposedGeneration = proposedGeneration
        self.freshHostKeyDigest = freshHostKeyDigest
        self.purposeClaim = purposeClaim
        self.requestIDClaim = requestIDClaim
        self.contractRevisionClaim = contractRevisionClaim
    }

    private static func isCanonicalSHA256Digest(_ value: String) -> Bool {
        let prefix = "sha256:"
        guard value.hasPrefix(prefix) else { return false }
        let hex = value.utf8.dropFirst(prefix.utf8.count)
        return hex.count == 64 && hex.allSatisfy {
            (0x30 ... 0x39).contains($0) || (0x61 ... 0x66).contains($0)
        }
    }
}
