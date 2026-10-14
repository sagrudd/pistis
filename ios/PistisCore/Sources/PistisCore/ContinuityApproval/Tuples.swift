import Foundation

/// Exact immutable UTC-second interval; no expiry grace or lifetime extension.
public struct ContinuityInterval: Equatable, Sendable {
    public let notBefore: UInt64
    public let notAfter: UInt64
    init(_ start: ContinuityValue, _ end: ContinuityValue) throws {
        notBefore = try start.number(); notAfter = try end.number()
        guard notBefore < notAfter else { throw ContinuityApprovalError.schema }
    }
    func contains(_ child: Self) -> Bool {
        notBefore <= child.notBefore && child.notAfter <= notAfter
    }
    func current(_ now: UInt64) -> Bool { notBefore <= now && now < notAfter }
}

/// Canonical PMCP scope facts only, not enrolled policy or effect authority.
public struct ContinuityScope: Sendable {
    public let site, host, service: Data
    public let hostEpoch, authorityEpoch, issuerGeneration: UInt64
    public let maintenanceOrigin, publicOrigin: String
    public let privateIPs: [String]
    public let serviceSPKI, rootSPKI, issuerSPKI: Data
    let value: ContinuityValue
    public var digest: Data { continuityDigest("Mnemosyne/Proxenos/scope/v1", value.encoded) }

    init(_ value: ContinuityValue) throws {
        let f = try value.fields(13)
        site = try f[0].data(16); host = try f[1].data(16); hostEpoch = try f[2].number()
        service = try f[3].data(16); maintenanceOrigin = try f[4].ascii(); publicOrigin = try f[5].ascii()
        let sans = try f[6].fields()
        guard !sans.isEmpty, sans.count <= 16 else { throw ContinuityApprovalError.schema }
        var prior = Data(); var ips: [String] = []
        for san in sans {
            let pair = try san.fields(2); let family = try pair[0].number()
            let address = try pair[1].data(family == 4 ? 4 : 16)
            let order = Data([UInt8(truncatingIfNeeded: family)]) + address
            guard prior.isEmpty || prior.lexicographicallyPrecedes(order) else { throw ContinuityApprovalError.schema }
            prior = order
            if family == 4 {
                let a = Array(address)
                guard a[0] == 10 || (a[0] == 172 && (16...31).contains(a[1]))
                    || (a[0] == 192 && a[1] == 168) else { throw ContinuityApprovalError.schema }
                ips.append(a.map(String.init).joined(separator: "."))
            } else if family == 6 {
                let a = Array(address)
                guard a[0] & 0xfe == 0xfc else { throw ContinuityApprovalError.schema }
                ips.append(stride(from: 0, to: 16, by: 2).map {
                    String(format: "%04x", UInt16(a[$0]) << 8 | UInt16(a[$0 + 1]))
                }.joined(separator: ":"))
            } else { throw ContinuityApprovalError.schema }
        }
        privateIPs = ips
        serviceSPKI = try f[7].data(32); rootSPKI = try f[8].data(32); issuerSPKI = try f[9].data(32)
        issuerGeneration = try f[10].number(); authorityEpoch = try f[12].number()
        do {
            _ = try SiteTrustEndpointIdentityV1(origin: maintenanceOrigin, tlsSPKISHA256: serviceSPKI)
            _ = try SiteTrustEndpointIdentityV1(origin: publicOrigin, tlsSPKISHA256: serviceSPKI)
        } catch { throw ContinuityApprovalError.schema }
        guard try f[11].number() == 1 else { throw ContinuityApprovalError.schema }
        self.value = value
    }
}

/// Exact finite PCIA allocation. Zero prior fields do not prove first installation.
public struct ContinuityAllocation: Sendable {
    public let scope: ContinuityScope
    public let operation, challenge, issuerID, enrollmentID, capabilityID, grantID: Data
    public let proxenosPeer, custodianPeer, witnessPeer, transportPin: Data
    public let issuerInterval, enrollmentInterval, capabilityInterval, grantInterval: ContinuityInterval
    public let capabilityGeneration, successorCap: UInt64
    let value: ContinuityValue
    public var canonicalBytes: Data { value.encoded }
    public var digest: Data { continuityDigest("Mnemosyne/Proxenos/continuity-initial-allocation/v1", canonicalBytes) }

    init(_ value: ContinuityValue) throws {
        let f = try value.fields(27)
        guard try f[0].ascii() == "PCIA/1", try f[1].data(32) == ContinuitySpecification.profile,
              try f[2].data(32) == ContinuitySpecification.callerProfile
        else { throw ContinuityApprovalError.binding }
        operation = try f[3].data(16); challenge = try f[4].data(32); scope = try ContinuityScope(f[5])
        issuerID = try f[6].data(16); issuerInterval = try ContinuityInterval(f[7], f[8])
        enrollmentID = try f[9].data(16); proxenosPeer = try f[10].data(16)
        custodianPeer = try f[11].data(16); witnessPeer = try f[12].data(16); transportPin = try f[13].data(32)
        enrollmentInterval = try ContinuityInterval(f[14], f[15]); capabilityID = try f[17].data(16)
        capabilityGeneration = try f[18].number(); capabilityInterval = try ContinuityInterval(f[19], f[20])
        grantID = try f[22].data(16); grantInterval = try ContinuityInterval(f[23], f[24])
        successorCap = try f[25].number()
        guard !operation.allSatisfy({ $0 == 0 }), !challenge.allSatisfy({ $0 == 0 }),
              capabilityGeneration != 0, successorCap <= 5,
              issuerInterval.contains(enrollmentInterval), enrollmentInterval.contains(capabilityInterval),
              capabilityInterval.contains(grantInterval),
              capabilityInterval.notAfter - capabilityInterval.notBefore <= 365 * 86400,
              grantInterval.notAfter - grantInterval.notBefore <= 365 * 86400,
              try [16,21,26].allSatisfy({ try f[$0].data(32).allSatisfy { $0 == 0 } })
        else { throw ContinuityApprovalError.binding }
        self.value = value
    }
}

/// Exact descriptor role/generation facts; a record digest alone is not provenance.
public struct ContinuityRoleKey: Sendable {
    public let role: String
    public let keyID, publicKey, generationDigest: Data
    public let interval: ContinuityInterval
    init(_ value: ContinuityValue, expected: String) throws {
        let f = try value.fields(6)
        role = try f[0].ascii(); keyID = try f[1].data(32); publicKey = try f[2].data(33)
        generationDigest = try f[3].data(32); interval = try ContinuityInterval(f[4], f[5])
        guard role == expected, keyID == (try continuityKeyID(publicKey)) else { throw ContinuityApprovalError.binding }
    }
}

/// Pinned exact contract, not support inferred from an app version or caller.
public enum ContinuitySpecification {
    public static let coordinate = "mnemosyne.proxenos.continuity-purpose-key-authority.v1"
    public static let digest = continuityHex("0b8047ec6cc5e3e6906af1163057895857800b69c54fa219d4bf93a34208b8ea")
    public static let profile = continuityHex("d1629d69264e8bf9dbd6bb6ed52c863f37aee2156fd032fded986839379ae5da")
    public static let callerProfile = continuityHex("77e1fbfedad6a5aae5cdcbb2230aa19431bd7034f4a05143bf120ce7bd06c303")
}
