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
            installationKeySHA256: Data(repeating: 3, count: 32),
            deviceID: Data(repeating: 8, count: 16),
            devicePublic: Data(base64Encoded: "A2sX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW")!,
            hostPublic: Data(repeating: 4, count: 32),
            phonePublic: Data(repeating: 5, count: 32),
            hostNonce: Data(repeating: 6, count: 32),
            phoneNonce: Data(repeating: 7, count: 32),
            issuedAt: 100, expiresAt: 200, siteDomain: "site.example"
        )
    }

    func testOfferMatchesRustVectorAndRejectsExpiry() throws {
        let qr = "MCP1:TUNQMQEBAQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDCAgICAgICAgICAgICAgICANrF9Hy4SxCR_i85uVjpEDydwN9gS3rM6D0oTlF2JjClgQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYAAAAAAAAAZAAAAAAAAADIwKgAwSD7AAxzaXRlLmV4YW1wbGU"
        let offer = try AttendedCustodyPairingOfferV1(qrText: qr, now: 150)
        XCTAssertEqual(offer.address, Data([192, 168, 0, 193]))
        XCTAssertEqual(offer.port, 8443)
        XCTAssertEqual(offer.deviceID, Data(repeating: 8, count: 16))
        XCTAssertThrowsError(try AttendedCustodyPairingOfferV1(qrText: qr, now: 200))
        XCTAssertThrowsError(try AttendedCustodyPairingOfferV1(qrText: qr + "=", now: 150))
    }

    func testTranscriptMatchesRustVectorAndRejectsExpiry() throws {
        let value = example()
        XCTAssertEqual(try value.encode(now: 150).count, 319)
        XCTAssertEqual(try value.digest(now: 150).map { String(format: "%02x", $0) }.joined(),
                       "79cdbf529cae3788dcb8a39cfd6b3b951ef71a6a14ff37716d0b38eef90e3c9a")
        XCTAssertThrowsError(try value.encode(now: 200))
        XCTAssertThrowsError(try value.encode(now: 99))
    }

    func testBothPeersDeriveSameSessionAndRejectWrongPeer() throws {
        let host = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 8, count: 32))
        let phone = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 9, count: 32))
        let transcript = AttendedCustodyPairingTranscriptV1(
            session: Data(repeating: 1, count: 16), installation: Data(repeating: 2, count: 16),
            installationKeySHA256: Data(repeating: 3, count: 32),
            deviceID: Data(repeating: 8, count: 16),
            devicePublic: Data(base64Encoded: "A2sX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW")!,
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
        XCTAssertEqual(h.shortAuthenticationString, "7615599324")
        XCTAssertEqual(h.hostToPhone.withUnsafeBytes { Data($0) }.map { String(format: "%02x", $0) }.joined(),
                       "5fdfce44c07a64b2cd1a5fd4fa43ef6af2a423382345b2fd77dfb186f25a9658")
        XCTAssertEqual(h.hostNoncePrefix.map { String(format: "%02x", $0) }.joined(), "10cc29c7")
        XCTAssertEqual(h.hostToPhone.withUnsafeBytes { Data($0) }, p.hostToPhone.withUnsafeBytes { Data($0) })
        XCTAssertNotEqual(h.hostToPhone.withUnsafeBytes { Data($0) }, h.phoneToHost.withUnsafeBytes { Data($0) })
        XCTAssertThrowsError(try hostEphemeral.derive(
            peerPublic: host.publicKey.rawRepresentation, transcript: transcript, localIsHost: true, now: 150))
        let lowOrder = Data([1] + Array(repeating: UInt8(0), count: 31))
        let invalid = AttendedCustodyPairingTranscriptV1(
            session: transcript.session, installation: transcript.installation,
            installationKeySHA256: transcript.installationKeySHA256, deviceID: transcript.deviceID,
            devicePublic: transcript.devicePublic, hostPublic: transcript.hostPublic,
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
                       "01000000000000000000000000009c3af0f444747215ec1cd6304301ee90")
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
