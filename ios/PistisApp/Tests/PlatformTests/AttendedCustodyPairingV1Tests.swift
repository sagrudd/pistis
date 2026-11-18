import Foundation
import CryptoKit
import XCTest
@testable import Pistis

final class AttendedCustodyPairingV1Tests: XCTestCase {
    private final class Results: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [Data] = []
        func append(_ value: Data) { lock.lock(); defer { lock.unlock() }; values.append(value) }
        func snapshot() -> [Data] { lock.lock(); defer { lock.unlock() }; return values }
    }
    private func example() -> AttendedCustodyPairingTranscriptV1 {
        AttendedCustodyPairingTranscriptV1(
            session: Data(repeating: 1, count: 16),
            installation: Data(repeating: 2, count: 16),
            targetIdentitySHA256: Data(repeating: 3, count: 32),
            hostPublic: Data(repeating: 4, count: 32),
            phonePublic: Data(repeating: 5, count: 32),
            hostNonce: Data(repeating: 6, count: 32),
            phoneNonce: Data(repeating: 7, count: 32),
            issuedAt: 100, expiresAt: 200, siteDomain: "site.example"
        )
    }

    func testTranscriptMatchesRustVectorAndRejectsExpiry() throws {
        let value = example()
        XCTAssertEqual(try value.encode(now: 150).count, 270)
        XCTAssertEqual(try value.digest(now: 150).map { String(format: "%02x", $0) }.joined(),
                       "59c7dfd2055a27a56a918f64d8aa6c3a56f27dbe24bd4779d70f590b6409acc8")
        XCTAssertThrowsError(try value.encode(now: 200))
        XCTAssertThrowsError(try value.encode(now: 99))
    }

    func testBothPeersDeriveSameSessionAndRejectWrongPeer() throws {
        let host = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 8, count: 32))
        let phone = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 9, count: 32))
        let transcript = AttendedCustodyPairingTranscriptV1(
            session: Data(repeating: 1, count: 16), installation: Data(repeating: 2, count: 16),
            targetIdentitySHA256: Data(repeating: 3, count: 32),
            hostPublic: host.publicKey.rawRepresentation, phonePublic: phone.publicKey.rawRepresentation,
            hostNonce: Data(repeating: 6, count: 32), phoneNonce: Data(repeating: 7, count: 32),
            issuedAt: 100, expiresAt: 200, siteDomain: "site.example"
        )
        let hostEphemeral = AttendedCustodyPairingEphemeralV1(testPrivateKey: host)
        let phoneEphemeral = AttendedCustodyPairingEphemeralV1(testPrivateKey: phone)
        let h = try hostEphemeral.derive(
            peerPublic: phone.publicKey.rawRepresentation, transcript: transcript, localIsHost: true, now: 150)
        let p = try phoneEphemeral.derive(
            peerPublic: host.publicKey.rawRepresentation, transcript: transcript, localIsHost: false, now: 150)
        XCTAssertEqual(h.shortAuthenticationString, p.shortAuthenticationString)
        XCTAssertEqual(h.shortAuthenticationString, "5678323698")
        XCTAssertEqual(h.hostToPhone.withUnsafeBytes { Data($0) }.map { String(format: "%02x", $0) }.joined(),
                       "69415cb10470035de9b854fdef8516ce623a5c36fcb70850412b14a37584f0f8")
        XCTAssertEqual(h.hostNoncePrefix.map { String(format: "%02x", $0) }.joined(), "5a359db2")
        XCTAssertEqual(h.hostToPhone.withUnsafeBytes { Data($0) }, p.hostToPhone.withUnsafeBytes { Data($0) })
        XCTAssertNotEqual(h.hostToPhone.withUnsafeBytes { Data($0) }, h.phoneToHost.withUnsafeBytes { Data($0) })
        XCTAssertThrowsError(try hostEphemeral.derive(
            peerPublic: host.publicKey.rawRepresentation, transcript: transcript, localIsHost: true, now: 150))
        let lowOrder = Data([1] + Array(repeating: UInt8(0), count: 31))
        let invalid = AttendedCustodyPairingTranscriptV1(
            session: transcript.session, installation: transcript.installation,
            targetIdentitySHA256: transcript.targetIdentitySHA256, hostPublic: transcript.hostPublic,
            phonePublic: lowOrder, hostNonce: transcript.hostNonce, phoneNonce: transcript.phoneNonce,
            issuedAt: 100, expiresAt: 200, siteDomain: "site.example")
        XCTAssertThrowsError(try AttendedCustodyPairingEphemeralV1(testPrivateKey: host).derive(
            peerPublic: lowOrder, transcript: invalid, localIsHost: true, now: 150))

        let digest = try transcript.digest(now: 150)
        let deadline = ContinuousClock().now.advanced(by: .seconds(10))
        let premature = try AttendedCustodyPairingExchangeV1(keys: p, deadline: deadline)
        XCTAssertThrowsError(try premature.request(kind: 1, payload: Data()))
        XCTAssertThrowsError(try AttendedCustodyPairingExchangeV1(keys: p, deadline: deadline))
        let fresh = try AttendedCustodyPairingEphemeralV1(testPrivateKey: phone).derive(
            peerPublic: host.publicKey.rawRepresentation, transcript: transcript, localIsHost: false, now: 150)
        let exchange = try AttendedCustodyPairingExchangeV1(keys: fresh, deadline: deadline)
        _ = try exchange.localConfirmation()
        let header = Data([1, 0] + Array(repeating: 0, count: 12))
        let nonce = p.hostNoncePrefix + Data(repeating: 0, count: 8)
        let box = try AES.GCM.seal(Data(), using: p.hostToPhone,
            nonce: AES.GCM.Nonce(data: nonce), authenticating: digest + header)
        let confirmation = header + box.ciphertext + box.tag
        XCTAssertEqual(confirmation.map { String(format: "%02x", $0) }.joined(),
                       "0100000000000000000000000000703bdc24833e9672d1c01a6f5eb7f7be")
        XCTAssertEqual(try exchange.receive(confirmation).0, 0)
        let results = Results()
        DispatchQueue.concurrentPerform(iterations: 16) { _ in
            if let record = try? exchange.request(kind: 1, payload: Data("x".utf8)) {
                results.append(record)
            }
        }
        let sent = results.snapshot()
        XCTAssertEqual(sent.count, 1)
        XCTAssertThrowsError(try exchange.receive(confirmation))
        XCTAssertThrowsError(try exchange.request(kind: 1, payload: Data()))
    }
}
