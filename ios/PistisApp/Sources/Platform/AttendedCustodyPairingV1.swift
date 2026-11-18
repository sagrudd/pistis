import CryptoKit
import Foundation

/// A scanned offer is untrusted until selected enrollment and SAS checks pass.
struct AttendedCustodyPairingOfferV1 {
    let session: Data
    let installation: Data
    let installationKeySHA256: Data
    let deviceID: Data
    let devicePublic: Data
    let hostPublic: Data
    let hostNonce: Data
    let issuedAt: UInt64
    let expiresAt: UInt64
    let address: Data
    let port: UInt16
    let siteDomain: String

    init(qrText: String, now: UInt64) throws {
        guard qrText.hasPrefix("MCP1:"), qrText.utf8.count <= 700 else { throw PlatformFailure.custodyRewrapUnavailable }
        let encoded = String(qrText.dropFirst(5))
        guard !encoded.isEmpty, encoded.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }) else { throw PlatformFailure.custodyRewrapUnavailable }
        let base64 = encoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard let bytes = Data(base64Encoded: base64 + String(repeating: "=", count: (4 - base64.count % 4) % 4)),
              bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") == encoded else { throw PlatformFailure.custodyRewrapUnavailable }
        let raw = [UInt8](bytes)
        guard raw.count >= 207, Array(raw[0..<5]) == [77, 67, 80, 49, 1] else { throw PlatformFailure.custodyRewrapUnavailable }
        func number(_ range: Range<Int>) -> UInt64 { raw[range].reduce(0) { ($0 << 8) | UInt64($1) } }
        let domainLength = Int(number(204..<206))
        guard domainLength > 0, domainLength <= 255, raw.count == 206 + domainLength,
              let domain = String(data: Data(raw[206...]), encoding: .utf8) else { throw PlatformFailure.custodyRewrapUnavailable }
        session = Data(raw[5..<21]); installation = Data(raw[21..<37]); installationKeySHA256 = Data(raw[37..<69])
        deviceID = Data(raw[69..<85]); devicePublic = Data(raw[85..<118])
        hostPublic = Data(raw[118..<150]); hostNonce = Data(raw[150..<182]); issuedAt = number(182..<190); expiresAt = number(190..<198)
        address = Data(raw[198..<202]); port = UInt16(number(202..<204)); siteDomain = domain
        let ip = [UInt8](address)
        guard [session, installation, installationKeySHA256, deviceID, hostPublic, hostNonce].allSatisfy({ $0.contains(where: { $0 != 0 }) }),
              devicePublic.first == 2 || devicePublic.first == 3,
              issuedAt <= now, expiresAt > now, expiresAt >= issuedAt, expiresAt - issuedAt <= 300,
              ip[0] != 0, ip[0] != 127, ip[0] < 224, !(ip[0] == 169 && ip[1] == 254), port != 0,
              domain.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [45, 46, 95].contains($0) }) else { throw PlatformFailure.custodyRewrapUnavailable }
        _ = try P256.Signing.PublicKey(compressedRepresentation: devicePublic)
    }
}

/// Compare an offer with independently retained enrollment and scoped App
/// Attest facts. The caller must obtain `devicePoint` from the existing key
/// without creating a key and retain/recheck these facts during the attempt.
func validateAttendedCustodyPairingOwnerV1(
    offer: AttendedCustodyPairingOfferV1,
    enrollment: AuthenticatedEnrollmentOutput,
    binding: ScopedAppAttestBinding,
    devicePoint: Data,
    now: Date
) throws {
    try binding.validate()
    let trust = enrollment.trust
    let ip = offer.address.map { String($0) }.joined(separator: ".")
    let keyID = Data(SHA256.hash(data: Data("pistis:key-id:v1\0".utf8) + devicePoint))
    guard trust.active, now < trust.expiresAt,
          trust.installationID == offer.installation,
          trust.installationPublicKey.count == 33,
          Data(SHA256.hash(data: trust.installationPublicKey)) == trust.fingerprint,
          trust.fingerprint == offer.installationKeySHA256,
          enrollment.responseContext.deviceID == offer.deviceID,
          enrollment.responseContext.deviceKeyID == keyID,
          devicePoint == offer.devicePublic,
          binding.installationID == offer.installation, binding.site == offer.siteDomain,
          binding.policyGeneration == trust.policyGeneration,
          binding.revocationGeneration == trust.revocationGeneration,
          let origin = URLComponents(string: enrollment.httpsOrigin),
          origin.scheme == "https", origin.host == ip,
          (origin.port ?? 443) == Int(offer.port), enrollment.allowedHosts.contains(ip)
    else { throw PlatformFailure.custodyRewrapUnavailable }
    _ = try P256.Signing.PublicKey(compressedRepresentation: devicePoint)
}

/// Public transcript facts only. Encoding does not authenticate a host or
/// authorize release of a retained recovery seed.
struct AttendedCustodyPairingTranscriptV1 {
    let session: Data
    let installation: Data
    let installationKeySHA256: Data
    let deviceID: Data
    let devicePublic: Data
    let hostPublic: Data
    let phonePublic: Data
    let hostNonce: Data
    let phoneNonce: Data
    let issuedAt: UInt64
    let expiresAt: UInt64
    let siteDomain: String

    func encode(now: UInt64) throws -> Data {
        let domain = Data(siteDomain.utf8)
        let fixed = [session, installation, installationKeySHA256, deviceID, devicePublic, hostPublic,
                     phonePublic, hostNonce, phoneNonce]
        guard fixed.map(\.count) == [16, 16, 32, 16, 33, 32, 32, 32, 32],
              fixed.allSatisfy({ $0.contains(where: { $0 != 0 }) }),
              issuedAt <= now, expiresAt > now, expiresAt >= issuedAt,
              expiresAt - issuedAt <= 300,
              (devicePublic.first == 2 || devicePublic.first == 3),
              !domain.isEmpty, domain.count <= 255,
              domain.allSatisfy({ byte in
                  (65...90).contains(byte) || (97...122).contains(byte)
                      || (48...57).contains(byte) || [45, 46, 95].contains(byte)
              }) else { throw PlatformFailure.custodyRewrapUnavailable }
        _ = try P256.Signing.PublicKey(compressedRepresentation: devicePublic)
        var out = Data("monas.attended-custody-recovery-pairing.v1\0".utf8)
        out.append(contentsOf: [0, 1, 1, 2, 1])
        for value in fixed { out.append(value) }
        for value in [issuedAt, expiresAt] {
            var big = value.bigEndian
            withUnsafeBytes(of: &big) { out.append(contentsOf: $0) }
        }
        var length = UInt16(domain.count).bigEndian
        withUnsafeBytes(of: &length) { out.append(contentsOf: $0) }
        out.append(domain)
        return out
    }

    func digest(now: UInt64) throws -> Data {
        Data(SHA256.hash(data: try encode(now: now)))
    }
}

/// Session derivation only. Callers must verify independently retained owner
/// facts and human confirmations before any recovery message is admitted.
final class AttendedCustodyPairingEphemeralV1 {
    private let lock = NSLock()
    private var privateKey: Curve25519.KeyAgreement.PrivateKey?
    let publicKey: Data

    init() {
        let key = Curve25519.KeyAgreement.PrivateKey()
        privateKey = key
        publicKey = key.publicKey.rawRepresentation
    }

    #if DEBUG
    init(testPrivateKey: Curve25519.KeyAgreement.PrivateKey) {
        privateKey = testPrivateKey
        publicKey = testPrivateKey.publicKey.rawRepresentation
    }
    #endif

    func derive(peerPublic: Data, transcript: AttendedCustodyPairingTranscriptV1,
                localIsHost: Bool, now: UInt64) throws -> AttendedCustodyPairingKeysV1 {
        lock.lock()
        let key = privateKey
        privateKey = nil
        lock.unlock()
        guard let key else { throw PlatformFailure.custodyRewrapUnavailable }
        return try AttendedCustodyPairingKeysV1.derive(privateKey: key, peerPublic: peerPublic,
            transcript: transcript, localIsHost: localIsHost, now: now)
    }
}

final class AttendedCustodyPairingKeysV1 {
    let hostToPhone: SymmetricKey
    let phoneToHost: SymmetricKey
    let hostNoncePrefix: Data
    let phoneNoncePrefix: Data
    let shortAuthenticationString: String
    fileprivate let transcriptDigest: Data
    private let claimLock = NSLock()
    private var claimed = false

    private init(hostToPhone: SymmetricKey, phoneToHost: SymmetricKey,
                 hostNoncePrefix: Data, phoneNoncePrefix: Data,
                 shortAuthenticationString: String, transcriptDigest: Data) {
        self.hostToPhone = hostToPhone; self.phoneToHost = phoneToHost
        self.hostNoncePrefix = hostNoncePrefix; self.phoneNoncePrefix = phoneNoncePrefix
        self.shortAuthenticationString = shortAuthenticationString
        self.transcriptDigest = transcriptDigest
    }

    fileprivate func claim() throws {
        claimLock.lock(); defer { claimLock.unlock() }
        guard !claimed else { throw PlatformFailure.custodyRewrapUnavailable }
        claimed = true
    }

    fileprivate static func derive(
        privateKey: Curve25519.KeyAgreement.PrivateKey,
        peerPublic: Data,
        transcript: AttendedCustodyPairingTranscriptV1,
        localIsHost: Bool,
        now: UInt64
    ) throws -> Self {
        let expectedLocal = localIsHost ? transcript.hostPublic : transcript.phonePublic
        let expectedPeer = localIsHost ? transcript.phonePublic : transcript.hostPublic
        guard privateKey.publicKey.rawRepresentation == expectedLocal,
              peerPublic == expectedPeer else { throw PlatformFailure.custodyRewrapUnavailable }
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublic)
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: peer)
        guard shared.withUnsafeBytes({ $0.contains(where: { $0 != 0 }) }) else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let salt = try transcript.digest(now: now)
        func key(_ label: String, count: Int) -> SymmetricKey {
            shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                sharedInfo: Data(label.utf8), outputByteCount: count)
        }
        func data(_ label: String, count: Int) -> Data {
            key(label, count: count).withUnsafeBytes { Data($0) }
        }
        let base = "monas.custody-pairing.v1."
        let limit: UInt64 = 18_446_744_070_000_000_000
        var sas: String?
        for counter in UInt32(0)..<128 {
            var big = counter.bigEndian
            var label = Data((base + "sas").utf8)
            withUnsafeBytes(of: &big) { label.append(contentsOf: $0) }
            let bytes = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                sharedInfo: label, outputByteCount: 8).withUnsafeBytes { Data($0) }
            let candidate = bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            if candidate < limit {
                sas = String(format: "%010llu", candidate % 10_000_000_000)
                break
            }
        }
        guard let sas else { throw PlatformFailure.custodyRewrapUnavailable }
        return Self(hostToPhone: key(base + "host-to-phone.key", count: 32),
                    phoneToHost: key(base + "phone-to-host.key", count: 32),
                    hostNoncePrefix: data(base + "host-to-phone.nonce", count: 4),
                    phoneNoncePrefix: data(base + "phone-to-host.nonce", count: 4),
                    shortAuthenticationString: sas, transcriptDigest: salt)
    }
}

/// Phone-side record protection. This is not an owner, peer, one-use or
/// deadline check; those must be held by the eventual carrier.
private final class AttendedCustodyPairingRecordsV1: @unchecked Sendable {
    private let lock = NSLock()
    private let keys: AttendedCustodyPairingKeysV1
    private let transcript: Data
    private var sendSequence: UInt64 = 0
    private var receiveSequence: UInt64 = 0
    private var localConfirmed = false
    private var remoteConfirmed = false
    private var closed = false

    init(keys: AttendedCustodyPairingKeysV1) throws {
        try keys.claim()
        self.keys = keys
        self.transcript = keys.transcriptDigest
    }

    /// Call only after the phone owner explicitly confirms the matching SAS.
    func localConfirmation() throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard !closed, !localConfirmed else { closed = true; throw PlatformFailure.custodyRewrapUnavailable }
        let record = try seal(kind: 0, plaintext: Data())
        localConfirmed = true
        return record
    }

    func sendMessage(kind: UInt8, plaintext: Data) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard !closed, localConfirmed, remoteConfirmed, (1...7).contains(kind) else {
            closed = true; throw PlatformFailure.custodyRewrapUnavailable
        }
        return try seal(kind: kind, plaintext: plaintext)
    }

    private func seal(kind: UInt8, plaintext: Data) throws -> Data {
        guard !closed, plaintext.count <= 32_768, sendSequence < UInt64.max else {
            closed = true; throw PlatformFailure.custodyRewrapUnavailable
        }
        do {
            var header = Data([2, kind])
            var sequence = sendSequence.bigEndian
            var length = UInt32(plaintext.count).bigEndian
            withUnsafeBytes(of: &sequence) { header.append(contentsOf: $0) }
            withUnsafeBytes(of: &length) { header.append(contentsOf: $0) }
            var nonce = keys.phoneNoncePrefix
            withUnsafeBytes(of: &sequence) { nonce.append(contentsOf: $0) }
            let box = try AES.GCM.seal(plaintext, using: keys.phoneToHost,
                nonce: AES.GCM.Nonce(data: nonce), authenticating: transcript + header)
            sendSequence += 1
            return header + box.ciphertext + box.tag
        } catch { closed = true; throw error }
    }

    func receive(_ record: Data) throws -> (UInt8, Data) {
        lock.lock(); defer { lock.unlock() }
        do { return try receiveInner(record) }
        catch { closed = true; throw error }
    }

    private func receiveInner(_ record: Data) throws -> (UInt8, Data) {
        let bytes = [UInt8](record)
        guard !closed, bytes.count >= 30, receiveSequence < UInt64.max else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        let kind = bytes[1]
        let sequence = bytes[2..<10].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let length = bytes[10..<14].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard bytes[0] == 1, sequence == receiveSequence, length <= 32_768,
              bytes.count == 14 + Int(length) + 16, kind <= 7 else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        if kind == 0 {
            guard !remoteConfirmed, length == 0 else { throw PlatformFailure.custodyRewrapUnavailable }
        } else {
            guard localConfirmed, remoteConfirmed else { throw PlatformFailure.custodyRewrapUnavailable }
        }
        var nonce = keys.hostNoncePrefix
        var bigSequence = sequence.bigEndian
        withUnsafeBytes(of: &bigSequence) { nonce.append(contentsOf: $0) }
        let header = Data(bytes[0..<14])
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: Data(bytes[14..<(14 + Int(length))]), tag: Data(bytes[(14 + Int(length))...]))
        let plaintext = try AES.GCM.open(box, using: keys.hostToPhone, authenticating: transcript + header)
        receiveSequence += 1
        if kind == 0 { remoteConfirmed = true }
        return (kind, plaintext)
    }
}

/// One serial recovery exchange. This does not itself establish owner facts,
/// a durable one-use claim, or authentication of the NUC custody peer.
final class AttendedCustodyPairingExchangeV1: @unchecked Sendable {
    private let lock = NSLock()
    private let records: AttendedCustodyPairingRecordsV1
    private let deadline: ContinuousClock.Instant
    private var nextKind: UInt8 = 1
    private var pending: UInt8?
    private var closed = false

    init(keys: AttendedCustodyPairingKeysV1, deadline: ContinuousClock.Instant) throws {
        let now = ContinuousClock().now
        guard deadline > now, deadline <= now.advanced(by: .seconds(300)) else {
            throw PlatformFailure.custodyRewrapUnavailable
        }
        self.records = try AttendedCustodyPairingRecordsV1(keys: keys)
        self.deadline = deadline
    }

    private func requireLive() throws {
        guard !closed, ContinuousClock().now < deadline else {
            closed = true; throw PlatformFailure.custodyRewrapUnavailable
        }
    }

    func localConfirmation() throws -> Data {
        lock.lock(); defer { lock.unlock() }
        do { try requireLive(); let value = try records.localConfirmation(); try requireLive(); return value }
        catch { closed = true; throw error }
    }

    func request(kind: UInt8, payload: Data) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        do {
            try requireLive()
            guard pending == nil, kind == nextKind else { throw PlatformFailure.custodyRewrapUnavailable }
            let value = try records.sendMessage(kind: kind, plaintext: payload)
            try requireLive(); pending = kind
            return value
        } catch { closed = true; throw error }
    }

    func receive(_ record: Data) throws -> (UInt8, Data) {
        lock.lock(); defer { lock.unlock() }
        do {
            try requireLive()
            let (kind, payload) = try records.receive(record)
            try requireLive()
            if kind == 0 { return (kind, payload) }
            guard pending == kind else { throw PlatformFailure.custodyRewrapUnavailable }
            pending = nil
            if kind == 7 { closed = true } else { nextKind += 1 }
            return (kind, payload)
        } catch { closed = true; throw error }
    }
}
