import Foundation

/// Immutable exact descriptor facts, not credential enrolment or live authority.
public struct ContinuityDescriptor: Sendable {
    public let site, rootSPKI, scopeDigest, issuerID, anchorKeyID: Data
    public let custodianPeer, custodianHost, operation, challenge, authorityState: Data
    public let revocationNamespace, approvalKeyID, allocationDigest: Data
    public let authorityEpoch, custodianHostEpoch: UInt64
    public let roles: [ContinuityRoleKey]
    public let interval: ContinuityInterval
    let value: ContinuityValue
    public var canonicalBytes: Data { value.encoded }
    public var digest: Data { continuityDigest("Mnemosyne/Proxenos/continuity-custody-binding/v1", canonicalBytes) }

    init(_ value: ContinuityValue, allocation: ContinuityAllocation) throws {
        let f = try value.fields(21)
        guard try f[0].ascii() == "PCCB/1", try f[1].data(32) == ContinuitySpecification.profile,
              try f[2].data(32) == ContinuitySpecification.callerProfile
        else { throw ContinuityApprovalError.binding }
        site = try f[3].data(16); rootSPKI = try f[4].data(32); authorityEpoch = try f[5].number()
        scopeDigest = try f[6].data(32); issuerID = try f[7].data(16); anchorKeyID = try f[8].data(32)
        custodianPeer = try f[9].data(16); custodianHost = try f[10].data(16); custodianHostEpoch = try f[11].number()
        operation = try f[12].data(16); challenge = try f[13].data(32); authorityState = try f[14].data(32)
        revocationNamespace = try f[15].data(16); approvalKeyID = try f[16].data(32)
        let keys = try f[17].fields(4)
        roles = try zip(keys, ["enrollment", "capability", "grant", "current-assertion"])
            .map { try ContinuityRoleKey($0.0, expected: $0.1) }
        interval = try ContinuityInterval(f[18], f[19]); allocationDigest = try f[20].data(32)
        self.value = value
        guard site == allocation.scope.site, rootSPKI == allocation.scope.rootSPKI,
              authorityEpoch == allocation.scope.authorityEpoch, scopeDigest == allocation.scope.digest,
              issuerID == allocation.issuerID, custodianPeer == allocation.custodianPeer,
              operation == allocation.operation, challenge == allocation.challenge,
              allocationDigest == allocation.digest, interval.contains(allocation.issuerInterval),
              anchorKeyID == roles[0].keyID, Set(roles.map(\.keyID)).count == 4,
              !roles.contains(where: { $0.keyID == approvalKeyID }),
              roles.allSatisfy({ $0.interval.contains(interval) })
        else { throw ContinuityApprovalError.binding }
    }
}

/// Exact validated public tuples and signature evidence only. No authority token.
/// Complete generation records are retained untrusted until a genuine local
/// provenance verifier checks them; hash equality is not treated as custody.
public struct ValidatedContinuityPresentation: Sendable {
    public let allocation: ContinuityAllocation
    public let descriptor: ContinuityDescriptor
    public let generationRecords: [Data]
    public let approvalPublicKey: Data
    public let excludedPublicKeys: [Data]

    /// Parse closed unsigned PCIA/PCCB bytes for review before any approval.
    /// The independent expected approval key never comes from the descriptor.
    public static func decode(
        allocationBytes: Data, descriptorBytes: Data, generationRecords: [Data],
        expectedApprovalPublicKey: Data, excludedPublicKeys: [Data]
    ) throws -> Self {
        let allocation = try ContinuityAllocation(ContinuityValue.decode(allocationBytes))
        let descriptor = try ContinuityDescriptor(ContinuityValue.decode(descriptorBytes), allocation: allocation)
        guard descriptor.approvalKeyID == (try continuityKeyID(expectedApprovalPublicKey)),
              generationRecords.count == 4, generationRecords.allSatisfy({ !$0.isEmpty }),
              !descriptor.roles.contains(where: { excludedPublicKeys.contains($0.publicKey) })
        else { throw ContinuityApprovalError.generation }
        return Self(allocation: allocation, descriptor: descriptor,
            generationRecords: generationRecords, approvalPublicKey: expectedApprovalPublicKey,
            excludedPublicKeys: excludedPublicKeys)
    }

    func descriptorEnvelope(_ bytes: Data) throws -> ContinuitySignedEnvelope {
        let envelope = try ContinuitySignedEnvelope(bytes, kind: .descriptor, publicKey: approvalPublicKey)
        guard envelope.body == descriptor.value else { throw ContinuityApprovalError.binding }
        return envelope
    }

    func selectionBody(_ bytes: Data, signedDescriptor: Data) throws -> ContinuityValue {
        _ = try descriptorEnvelope(signedDescriptor)
        let value = try ContinuityValue.decode(bytes), s = try value.fields(18)
        let d = try descriptor.value.fields(21)
        guard try s[0].ascii() == "PCMS/1", try s[1].ascii() == ContinuitySpecification.coordinate,
              try s[2].data(32) == ContinuitySpecification.digest,
              try s[3].data(32) == ContinuitySpecification.profile,
              try s[4].data(32) == ContinuitySpecification.callerProfile,
              try s[5].data(32) == descriptor.digest,
              try s[6].data(32) == continuityDigest("Mnemosyne/Proxenos/continuity-enrollment-origin/v1", signedDescriptor)
        else { throw ContinuityApprovalError.binding }
        for (si, di) in [(7,3),(8,4),(9,5),(10,6),(11,12),(12,13),(13,14),(14,15),(15,16)] {
            guard s[si] == d[di] else { throw ContinuityApprovalError.binding }
        }
        guard descriptor.interval.contains(try ContinuityInterval(s[16], s[17])) else {
            throw ContinuityApprovalError.expired
        }
        return value
    }

    /// Verify exact PCMS/1 evidence. This never establishes a current selection context.
    public func verifySelection(_ bytes: Data, signedDescriptor: Data) throws -> Data {
        let envelope = try ContinuitySignedEnvelope(bytes, kind: .selection, publicKey: approvalPublicKey)
        _ = try selectionBody(envelope.body.encoded, signedDescriptor: signedDescriptor)
        return continuityDigest("Mnemosyne/Proxenos/continuity-mode-selection-envelope/v1", bytes)
    }

    func issuerBody(signedDescriptor: Data) throws -> ContinuityValue {
        _ = try descriptorEnvelope(signedDescriptor)
        return .array([
            .bytes(Data("PCII/1".utf8)), .bytes(descriptor.site), .uint(descriptor.authorityEpoch),
            .bytes(allocation.issuerID), .bytes(descriptor.anchorKeyID), .bytes(descriptor.rootSPKI),
            .uint(allocation.issuerInterval.notBefore), .uint(allocation.issuerInterval.notAfter),
            .bytes(continuityDigest("Mnemosyne/Proxenos/continuity-enrollment-origin/v1", signedDescriptor)),
            .bytes(descriptor.revocationNamespace), .bytes(descriptor.digest), .array([.uint(1)])
        ])
    }

    /// Verify unchanged PCII wire fields against exact committed allocation and selection.
    /// A valid signature alone does not confer current issuance authority.
    public func verifyIssuer(_ bytes: Data, signedDescriptor: Data, signedSelection: Data) throws {
        _ = try verifySelection(signedSelection, signedDescriptor: signedDescriptor)
        let envelope = try ContinuitySignedEnvelope(bytes, kind: .issuer, publicKey: approvalPublicKey)
        guard envelope.body == (try issuerBody(signedDescriptor: signedDescriptor)) else {
            throw ContinuityApprovalError.binding
        }
    }

    func current(_ now: UInt64) -> Bool {
        [descriptor.interval, allocation.issuerInterval, allocation.enrollmentInterval,
         allocation.capabilityInterval, allocation.grantInterval].allSatisfy { $0.current(now) }
    }
}
