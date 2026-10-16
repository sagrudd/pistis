import Foundation
import XCTest
@testable import PistisCore
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#endif

final class IssuerJointRootAttendanceTests: XCTestCase {
    func testCurrentSitePreparationUsesClosedExistingWireAndRejectsMalformedInputs() throws {
        let nonce = Data(repeating: 0x11, count: 32)
        let target = Data(repeating: 0x22, count: 32)
        // Normative four-field CBOR vector, independent of the private encoder.
        let expected = Data([0x84, 0x01, 0x58, 0x1e]) + Data("issuer-site-current-prepare-v1".utf8)
            + Data([0x58, 0x20]) + nonce + Data([0x58, 0x20]) + target
        XCTAssertEqual(try IssuerPhoneWire.currentSitePreparationRequest(
            nonce: nonce, currentACKTarget: target), expected)
        for invalid in [Data(), Data(repeating: 1, count: 31), Data(repeating: 1, count: 33), Data(repeating: 0, count: 32)] {
            XCTAssertThrowsError(try IssuerPhoneWire.currentSitePreparationRequest(
                nonce: invalid, currentACKTarget: target))
        }
        for invalid in [Data(), Data(repeating: 1, count: 31), Data(repeating: 1, count: 33)] {
            XCTAssertThrowsError(try IssuerPhoneWire.currentSitePreparationRequest(
                nonce: nonce, currentACKTarget: invalid))
        }
    }

    func testPinnedExistingActionAndExactSuccessorProduceExistingResponseOnly() throws {
        let f = try Fixture()
        let value = try IssuerJointRootAttendance(fileBytes: f.wrapper, trust: f.trust,
            responseContext: f.context, nowMilliseconds: 110_000)
        let payload = try value.approvedResponsePayload(issuedAt: 110_000, verifiedAt: 110_100)
        let fields = try JointActionCBOR.decode(payload).map(13)
        XCTAssertEqual(try fields[1].text(), "pistis.action-approval-response.v2")
        XCTAssertEqual(try fields[5].data(), f.context.deviceKeyID)
        XCTAssertEqual(try fields[7].data(), Data(repeating: 17, count: 32))
        let envelope = try f.sign(payload, using: f.device)
        let original = try IssuerCBOR.decode(value.original(signedResponse: envelope), maximum: 16_384).array(4)
        XCTAssertEqual(try original[1].bytes(), f.control)
        XCTAssertEqual(try original[2].bytes(), f.challenge)
        XCTAssertEqual(try original[3].bytes(), envelope)
        XCTAssertThrowsError(try value.approvedResponsePayload(issuedAt: 110_000, verifiedAt: 140_000))
    }
    func testChangedControlCounterAndWrongSignatureDenyBeforeAResponseExists() throws {
        let f = try Fixture()
        var joint = try IssuerCBOR.decode(f.control).array(13)
        var successor = try IssuerCBOR.decode(joint[9].bytes()).array(37)
        successor[13] = .unsigned(99) // Binding generation may never change.
        joint[9] = .bytes(try IssuerCBOR.array(successor).encoded())
        let changed = try IssuerCBOR.array([.unsigned(1), .bytes(Data("pistis-issuer-joint-root-attendance.v1".utf8)),
            .bytes(try IssuerCBOR.array(joint).encoded()), .bytes(f.challenge)]).encoded()
        XCTAssertThrowsError(try IssuerJointRootAttendance(fileBytes: changed, trust: f.trust, responseContext: f.context, nowMilliseconds: 110_000))
        var damaged = f.wrapper; damaged[damaged.count - 1] ^= 1
        XCTAssertThrowsError(try IssuerJointRootAttendance(fileBytes: damaged, trust: f.trust, responseContext: f.context, nowMilliseconds: 110_000))
        XCTAssertThrowsError(try IssuerJointRootAttendance(fileBytes: f.wrapper, trust: f.trust, responseContext: f.context, nowMilliseconds: 140_000))
    }
    func testPrivateActionCodecRejectsReorderedNonminimalAndTrailingMaps() throws {
        XCTAssertThrowsError(try JointActionCBOR.decode(Data([0xa1, 0x01, 0x01])))
        XCTAssertThrowsError(try JointActionCBOR.decode(Data([0xa1, 0x18, 0x00, 0x01])))
        XCTAssertThrowsError(try JointActionCBOR.decode(Data([0xa1, 0x00, 0x01, 0x00])))
        XCTAssertThrowsError(try JointActionCBOR.decode(Data(repeating: 0, count: 16_385)))
    }
    func testInstallationSignedExtraIntentDeniesBeforeResponse() throws {
        for mutation in 1...7 {
            let f = try Fixture(intentMutation: mutation)
            XCTAssertThrowsError(try IssuerJointRootAttendance(fileBytes: f.wrapper,
                trust: f.trust, responseContext: f.context, nowMilliseconds: 110_000))
        }
    }
    func testInstallationSignedMalformedUsernameAndNilStatusGrantDeny() throws {
        let usernames: [JointActionCBOR] = [.number(12), .string(""), .string(String(repeating: "x", count: 129))]
        for username in usernames {
            let f = try Fixture(username: username)
            XCTAssertThrowsError(try IssuerJointRootAttendance(fileBytes: f.wrapper,
                trust: f.trust, responseContext: f.context, nowMilliseconds: 110_000))
        }
        let f = try Fixture(nilStatusGrant: true)
        XCTAssertThrowsError(try IssuerJointRootAttendance(fileBytes: f.wrapper,
            trust: f.trust, responseContext: f.context, nowMilliseconds: 110_000))
    }
    func testCurrentPermissionRejoinsCompleteSignedConsentAndIADMWithoutRenewingAttendance() throws {
        let f = try Fixture(siteCurrent: true)
        let attendance = try IssuerJointRootAttendance(fileBytes: f.wrapper, trust: f.trust,
            responseContext: f.context, nowMilliseconds: 110_000)
        let signed = try f.sign(attendance.approvedResponsePayload(issuedAt: 110_000, verifiedAt: 110_100), using: f.device)
        let original = try attendance.original(signedResponse: signed)
        let joint = try IssuerCBOR.decode(f.control).array(13)
        let status = try IssuerCBOR.decode(joint[3].bytes()).array(7)
        let evidence = try IssuerCBOR.array([.unsigned(1), .bytes(Data("issuer-site-current-owner-evidence-v1".utf8)),
            .bytes(f.admission), .bytes(original), status[2], .unsigned(0), .unsigned(1)]).encoded()
        let tuple = try IssuerCBOR.decode(joint[8].bytes()).array(37)
        let target = Data(SHA256.hash(data: attendance.sitePublicKey))
        let installation = try IssuerCBOR.decode(status[2].bytes()).array(16)[4]
        let readinessBytes = try IssuerCBOR.array([.unsigned(1), .bytes(Data(repeating: 8, count: 16)), .unsigned(2), installation,
            .bytes(attendance.siteID), .bytes(Data("fixture".utf8)), .bytes(target), tuple[22], tuple[23], tuple[24],
            .bytes(Data(SHA256.hash(data: tuple[25].bytes(33)))), .unsigned(149), .bytes(evidence), .bytes(Data(repeating: 9, count: 32))]).encoded()
        let readiness = try IssuerPhoneReadiness(canonicalBytes: readinessBytes)
        let current = try IssuerSiteCurrentPermissionEvidence(readiness: readiness, trust: f.trust,
            responseContext: f.context, currentACKTarget: target, policyGeneration: 4,
            revocationGeneration: 6, nowMilliseconds: 145_000)
        XCTAssertEqual(current.rootAdmissionReference, IssuerCheckpointEnvelope.reference(f.admission, kind: .admission))
        XCTAssertEqual(current.revocationRevision, 0)
        XCTAssertThrowsError(try IssuerSiteCurrentPermissionEvidence(readiness: readiness, trust: f.trust,
            responseContext: f.context, currentACKTarget: target, policyGeneration: 3,
            revocationGeneration: 6, nowMilliseconds: 145_000))
        XCTAssertThrowsError(try IssuerSiteCurrentPermissionEvidence(readiness: readiness, trust: f.trust,
            responseContext: f.context, currentACKTarget: Data(repeating: 1, count: 32), policyGeneration: 4,
            revocationGeneration: 6, nowMilliseconds: 145_000))
        XCTAssertThrowsError(try IssuerSiteCurrentPermissionEvidence(readiness: readiness, trust: f.trust,
            responseContext: f.context, currentACKTarget: target, policyGeneration: 4,
            revocationGeneration: 6, nowMilliseconds: 150_000))
    }
    /// Deterministic TEST keys and signed packets only. No installed or native
    /// owner is constructed and no Keychain/Secure Enclave API is invoked.
    private struct Fixture {
        let installation: P256.Signing.PrivateKey
        let device: P256.Signing.PrivateKey
        let admission: Data
        let control: Data
        let challenge: Data
        let wrapper: Data
        let trust: InstallationTrustRecord
        let context: DeviceResponseContext
        init(intentMutation: Int = 0, username: JointActionCBOR = .string("operator"), nilStatusGrant: Bool = false, siteCurrent: Bool = false) throws {
            func key(_ n: UInt8) throws -> P256.Signing.PrivateKey {
                try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0, count: 31) + Data([n]))
            }
            func id(_ n: UInt8) -> Data { Data(repeating: n, count: 16) }
            func digest(_ n: UInt8) -> Data { Data(repeating: n, count: 32) }
            let installation = try key(1), root = try key(2), device = try key(3), witness = try key(4)
            let ip = installation.publicKey.compressedRepresentation
            let rp = root.publicKey.compressedRepresentation, dp = device.publicKey.compressedRepresentation
            let wp = witness.publicKey.compressedRepresentation
            let ik = Data(SHA256.hash(data: Data("pistis:key-id:v1\0".utf8) + ip))
            let dk = Data(SHA256.hash(data: Data("pistis:key-id:v1\0".utf8) + dp))
            let rootHash = Data(SHA256.hash(data: rp))
            let installID = id(4)
            let b = [UInt8](installID)
            let installText = UUID(uuid: (b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15])).uuidString.lowercased()
            let checkpoint = IssuerCBOR.array([.bytes(Data("ICKP/1".utf8)), .unsigned(0), .bytes(Data(repeating: 0, count: 32)), .unsigned(0), .bytes(Data(repeating: 0, count: 32))])
            let state = IssuerCBOR.array([.bytes(Data("IIST/1".utf8)), .unsigned(1), .bytes(Data("1".utf8)), .bytes(digest(55)), checkpoint,
                .bytes(digest(56)), .bytes(digest(57)), .bytes(Data("fixture".utf8)), .bytes(digest(58)), .unsigned(0), .unsigned(0), .unsigned(0)])
            let parameters = IssuerCBOR.array([.bytes(Data("IADM/1".utf8)), .bytes(id(22)), .bytes(Data(installText.utf8)), .bytes(Data("fixture".utf8)),
                .bytes(Data("classic-commit-status:mnemosyne/expedition".utf8)), .bytes(Data("thesaurophylax.github-exact-source-qualification-credential-projection.v1".utf8)),
                .unsigned(1), .unsigned(1), .bytes(wp), .bytes(try key(5).publicKey.compressedRepresentation), .bytes(try key(6).publicKey.compressedRepresentation),
                checkpoint, state, .bytes(digest(19)), .bytes(digest(60)), .bytes(digest(61)), .bytes(Data("fixture".utf8)), .bytes(digest(62)),
                .bytes(Data("1".utf8)), .bytes(digest(63)), .unsigned(1)])
            let admissionBody = try IssuerCheckpointBody(canonicalBytes: parameters.encoded(), kind: .admission)
            let admissionSignature = Self.lowS(try root.signature(for: admissionBody.signaturePreimage).rawRepresentation)
            let admission = try IssuerCheckpointEnvelope.encode(body: admissionBody, sitePublicKey: rp, signature: admissionSignature)
            self.admission = admission
            let admissionHash = siteCurrent ? Data(SHA256.hash(data: admission)) : digest(21)
            let old: [IssuerCBOR] = [.unsigned(1), .bytes(Data("issuer-site-status-root-owner-tuple-v1".utf8)),
                .bytes(id(2)), .unsigned(10), .bytes(installID), .bytes(id(5)), .bytes(rp),
                .bytes(id(7)), .bytes(id(8)), .bytes(id(9)), .bytes(Data(dk.map { String(format: "%02x", $0) }.joined().utf8)),
                .unsigned(1), .unsigned(1), .unsigned(1), .bytes(id(14)), .unsigned(3), .unsigned(5), .unsigned(5),
                .bytes(id(18)), .bytes(digest(19)), .bytes(digest(20)), .bytes(admissionHash), .bytes(id(22)),
                .unsigned(1), .unsigned(1), .bytes(wp), .unsigned(90), .unsigned(1000), .unsigned(90),
                .unsigned(200), .unsigned(1000), .unsigned(100), .unsigned(150), .unsigned(200), .bytes(ip), .bytes(rootHash), .bytes(dp)]
            var next = old
            for i in [3, 15, 16, 17] { next[i] = .unsigned(try old[i].uint() + 1) }
            let scope = try IssuerCBOR.array([.unsigned(1), .bytes(Data("IssueIssuerRootCurrentStatus".utf8)), .bytes(nilStatusGrant ? Data(repeating: 0, count: 16) : id(99)),
                .bytes(id(7)), .bytes(Data(installText.utf8)), .bytes(id(5)), .bytes(rootHash), .bytes(admissionHash),
                .bytes(id(22)), .unsigned(1), .unsigned(1), .bytes(Data(SHA256.hash(data: wp))),
                .unsigned(100), .unsigned(150), .unsigned(4), .unsigned(6)]).encoded()
            let status = try IssuerCBOR.array([.unsigned(1), .bytes(Data("ProvisionIssuerRootCurrentStatusPermission".utf8)),
                .bytes(scope), .bytes(id(14)), .bytes(digest(17)), .unsigned(100), .unsigned(140)]).encoded()
            let control = try IssuerCBOR.array([.unsigned(1), .bytes(Data("ProvisionIssuerSiteStatusAndContinueRootV1".utf8)),
                .bytes(id(33)), .bytes(status), .bytes(id(18)), .bytes(digest(19)), .bytes(digest(20)), .bytes(admissionHash),
                .bytes(try IssuerCBOR.array(old).encoded()), .bytes(try IssuerCBOR.array(next).encoded()),
                .bytes(digest(17)), .unsigned(100), .unsigned(140)]).encoded()
            let executable = "/usr/libexec/mnemosyne-monas/monas-server"
            var fields: [JointActionCBOR] = [.number(2), .string("pistis.action-descriptor.v2"),
                .string(executable), .bytes(digest(3)), .list([.string(executable)]), .string("/"), .list([]),
                .list([.object([.number(1), .string("urn:mnemosyne:issuer-control:ProvisionIssuerSiteStatusAndContinueRootV1"), .bytes(Data(SHA256.hash(data: control)))])])]
            switch intentMutation {
            case 1: fields[2] = .string("/bin/sh")
            case 2: fields[4] = .list([.string(executable), .string("--extra-effect")])
            case 3: fields[5] = .string("/tmp")
            case 4: fields[6] = .list([.object([.string("EXTRA"), .string("intent")])])
            case 5: fields[7] = .list(try fields[7].array() + [.object([.number(2), .string("/tmp/extra-output"), .null])])
            case 6: fields[3] = .bytes(Data(repeating: 0, count: 32))
            case 7:
                fields[7] = .list([.object([.number(3), .string("urn:mnemosyne:issuer-control:ProvisionIssuerSiteStatusAndContinueRootV1"), .bytes(Data(SHA256.hash(data: control)))])])
            default: break
            }
            let descriptor = try JointActionCBOR.object(fields).encoded()
            let payload = try JointActionCBOR.object([.number(2), .string("pistis.action-approval-challenge.v2"),
                .number(100_000), .number(140_000), .bytes(installID), .bytes(ik), .bytes(id(6)), .bytes(digest(17)),
                .bytes(id(7)), .bytes(id(88)), .string("propylaion"), .string("Test installation"), username,
                .bytes(Data(SHA256.hash(data: ip))), .bytes(descriptor)]).encoded()
            self.installation = installation; self.device = device; self.control = control
            self.trust = try InstallationTrustRecord(installationID: installID, displayName: "Test installation", audience: "propylaion",
                authorisedProductAudiences: ["propylaion"], userID: id(7), externalIdentityID: id(88),
                fingerprint: Data(SHA256.hash(data: ip)), installationKeyID: ik, installationPublicKey: ip,
                authorityKeyID: digest(77), authorityReceipt: Data([1]), policyGeneration: 3, revocationGeneration: 5,
                expiresAt: Date(timeIntervalSince1970: 1000), active: true)
            self.context = try DeviceResponseContext(deviceID: id(9), deviceKeyID: dk, userID: id(7), externalIdentityID: id(88))
            let signature = Self.lowS(try installation.signature(for: CoseSign1.signatureStructure(keyID: ik, payload: payload)).rawRepresentation)
            let challenge = try CoseSign1(keyID: ik, payload: payload, signature: signature).encoded()
            self.challenge = challenge
            self.wrapper = try IssuerCBOR.array([.unsigned(1), .bytes(Data("pistis-issuer-joint-root-attendance.v1".utf8)), .bytes(control), .bytes(challenge)]).encoded()
        }
        func sign(_ payload: Data, using key: P256.Signing.PrivateKey) throws -> Data {
            let id = Data(SHA256.hash(data: Data("pistis:key-id:v1\0".utf8) + key.publicKey.compressedRepresentation))
            let signature = Self.lowS(try key.signature(for: CoseSign1.signatureStructure(keyID: id, payload: payload)).rawRepresentation)
            return try CoseSign1(keyID: id, payload: payload, signature: signature).encoded()
        }
        private static func lowS(_ signature: Data) -> Data {
            let order: [UInt8] = [0xff,0xff,0xff,0xff,0,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51]
            let half = Data([0x7f,0xff,0xff,0xff,0x80,0,0,0,0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xde,0x73,0x7d,0x56,0xd3,0x8b,0xcf,0x42,0x79,0xdc,0xe5,0x61,0x7e,0x31,0x92,0xa8])
            let scalar = Data(signature.suffix(32))
            if scalar.lexicographicallyPrecedes(half) || scalar == half { return signature }
            var bytes = [UInt8](scalar), borrow = 0
            for i in stride(from: 31, through: 0, by: -1) {
                var n = Int(order[i]) - Int(bytes[i]) - borrow
                if n < 0 { n += 256; borrow = 1 } else { borrow = 0 }; bytes[i] = UInt8(n)
            }
            return Data(signature.prefix(32)) + Data(bytes)
        }
    }
}
