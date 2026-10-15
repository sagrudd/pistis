import Foundation
import XCTest
@testable import PistisCore
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

final class IssuerSiteRootTests: XCTestCase {
    private let installation = Data("00000000-0000-0000-0000-000000000001".utf8)
    private func readiness(mode: IssuerPhoneMode = .currentStatusPair, siteKeyID: Data = Data(repeating: 3, count: 32)) throws -> IssuerPhoneReadiness {
        try IssuerPhoneReadiness(canonicalBytes: IssuerCBOR.array([
            .unsigned(1), .bytes(Data(repeating: 1, count: 16)), .unsigned(mode.rawValue),
            .bytes(installation), .bytes(Data(repeating: 2, count: 16)), .bytes(Data("Site-Alpha".utf8)),
            .bytes(siteKeyID), .bytes(Data(repeating: 4, count: 16)),
            .unsigned(1), .unsigned(1), .bytes(Data(repeating: 5, count: 32)), .unsigned(9999999999),
            .bytes(Data([1])), .bytes(Data(repeating: 6, count: 32)),
        ]).encoded())
    }
    private func status(nonce: UInt8 = 7, serial: UInt64 = 1) throws -> Data {
        try IssuerCBOR.array([
            .bytes(Data("IRCS/1".utf8)), .bytes(Data(repeating: 8, count: 32)),
            .bytes(Data(repeating: 4, count: 16)), .unsigned(1), .unsigned(1),
            .bytes(Data(repeating: 5, count: 32)), .unsigned(9), .unsigned(1),
            .bytes(Data(repeating: nonce, count: 32)),
            .bytes(Data("00000000-0000-0000-0000-000000000003".utf8)), .unsigned(serial),
        ]).encoded()
    }
    private func task(_ readiness: IssuerPhoneReadiness, kind: IssuerPhoneTask.Kind = .pre,
                      body: Data, reference: Data = Data()) throws -> IssuerPhoneTask {
        try IssuerPhoneTask(canonicalBytes: IssuerCBOR.array([
            .unsigned(1), .bytes(readiness.ceremonyID), .unsigned(kind.rawValue),
            .unsigned(kind == .post ? 2 : 1), .bytes(body), .bytes(reference), .bytes(readiness.digest),
        ]).encoded())
    }
    private func lowS(_ bytes: Data) -> Data {
        let order: [UInt8] = [0xff,0xff,0xff,0xff,0,0,0,0,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51]
        let half: [UInt8] = [0x7f,0xff,0xff,0xff,0x80,0,0,0,0x7f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xde,0x73,0x7d,0x56,0xd3,0x8b,0xcf,0x42,0x79,0xdc,0xe5,0x61,0x7e,0x31,0x92,0xa8]
        let s = Array(bytes.suffix(32))
        guard half.lexicographicallyPrecedes(s) else { return bytes }
        var out = [UInt8](repeating: 0, count: 32), borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            var delta = Int(order[i]) - Int(s[i]) - borrow
            if delta < 0 { delta += 256; borrow = 1 } else { borrow = 0 }
            out[i] = UInt8(delta)
        }
        return bytes.prefix(32) + Data(out)
    }
    func testClosedCanonicalCodecRejectsHostileAllocationsAndUnknownFamilies() throws {
        for raw in [Data([0x9f,0xff]), Data([0x18,0x01]), Data([0x60]), Data([0xa0]), Data([0x80,0x00]), Data([0x9b,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff])] {
            XCTAssertThrowsError(try IssuerCBOR.decode(raw))
        }
        XCTAssertThrowsError(try IssuerCBOR.decode(Data(repeating: 0, count: 262145)))
        let ready = try readiness()
        XCTAssertEqual(try IssuerCBOR.decode(ready.canonicalBytes).encoded(), ready.canonicalBytes)
        XCTAssertEqual(ready.digest, IssuerPhoneWire.sha256(ready.canonicalBytes))
        var a = try IssuerCBOR.decode(ready.canonicalBytes).array(14)
        a[2] = .unsigned(3)
        XCTAssertThrowsError(try IssuerPhoneReadiness(canonicalBytes: IssuerCBOR.array(a).encoded()))
        a[2] = .unsigned(1); a[9] = .unsigned(2)
        XCTAssertThrowsError(try IssuerPhoneReadiness(canonicalBytes: IssuerCBOR.array(a).encoded()))
    }
    func testOriginalThirtySecondAndTwoSecondBoundsNeverRenew() throws {
        let start = ContinuousClock().now
        var operation = try IssuerPhoneOperation(readiness: readiness(), rootAdmissionReference: Data(repeating: 8, count: 32), preparedAt: start)
        try operation.faceAuthenticated(at: start.advanced(by: .seconds(1)))
        try operation.arm(at: start.advanced(by: .milliseconds(1100)))
        let end = try XCTUnwrap(operation.originalDeadline)
        XCTAssertEqual(end, start.advanced(by: .milliseconds(3100)))
        XCTAssertThrowsError(try operation.checkCurrent(at: end))
        XCTAssertThrowsError(try operation.arm(at: end))
        var late = try IssuerPhoneOperation(readiness: readiness(), rootAdmissionReference: Data(repeating: 8, count: 32), preparedAt: start)
        XCTAssertThrowsError(try late.faceAuthenticated(at: start.advanced(by: .seconds(30))))
        var queued = try IssuerPhoneOperation(readiness: readiness(), rootAdmissionReference: Data(repeating: 8, count: 32), preparedAt: start)
        try queued.faceAuthenticated(at: start)
        XCTAssertThrowsError(try queued.arm(at: start.advanced(by: .milliseconds(251))))
    }
    func testBiometricCallbackTimestampIncludesDelayedContinuationResumption() throws {
        let preparedAt = ContinuousClock().now
        let callbackAt = preparedAt.advanced(by: .seconds(1))
        let resumedAt = callbackAt.advanced(by: .milliseconds(251))
        var operation = try IssuerPhoneOperation(readiness: readiness(), rootAdmissionReference: Data(repeating: 8, count: 32), preparedAt: preparedAt)
        // Production records callbackAt before resuming, rather than taking a
        // new instant when its awaiting task eventually reaches the executor.
        try operation.faceAuthenticated(at: callbackAt)
        XCTAssertThrowsError(try operation.arm(at: resumedAt))
        XCTAssertNil(operation.originalDeadline)
    }

    func testTwoActualFixtureSignaturesUseExactDomainsAndStrictPreEnvelopeReference() throws {
        // Deterministic software test key only; no LAContext/native owner claim.
        let key = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 11, count: 32))
        let publicKey = key.publicKey.compressedRepresentation
        let ready = try readiness(siteKeyID: IssuerPhoneWire.sha256(publicKey))
        let start = ContinuousClock().now
        var operation = try IssuerPhoneOperation(readiness: ready, rootAdmissionReference: Data(repeating: 8, count: 32), preparedAt: start)
        try operation.faceAuthenticated(at: start); try operation.arm(at: start)
        let pre = try task(ready, body: status())
        try operation.beginSignature(pre, at: start)
        let signature = try key.signature(for: pre.body.signaturePreimage)
        let envelope = try IssuerCheckpointEnvelope.encode(body: pre.body, sitePublicKey: publicKey, signature: lowS(signature.rawRepresentation))
        try operation.signatureCompleted(task: pre, envelope: envelope, sitePublicKey: publicKey, at: start)
        XCTAssertEqual(try operation.exactCompletedReply(for: pre, at: start), envelope)
        let reference = IssuerCheckpointEnvelope.reference(envelope, kind: .currentStatus)
        XCTAssertNotEqual(reference, IssuerPhoneWire.sha256(pre.body.canonicalBytes))
        let post = try task(ready, kind: .post, body: status(nonce: 12, serial: 2), reference: reference)
        try operation.beginSignature(post, at: start)
        let postSignature = try key.signature(for: post.body.signaturePreimage)
        let postEnvelope = try IssuerCheckpointEnvelope.encode(body: post.body, sitePublicKey: publicKey, signature: lowS(postSignature.rawRepresentation))
        try operation.signatureCompleted(task: post, envelope: postEnvelope, sitePublicKey: publicKey, at: start)
        let terminal = try IssuerCBOR.array([.unsigned(1), .bytes(ready.ceremonyID), .unsigned(0)]).encoded()
        try operation.finish(terminal, at: start)
        XCTAssertThrowsError(try operation.beginSignature(post, at: start))
        XCTAssertThrowsError(try operation.exactCompletedReply(for: post, at: start))
    }
    func testAdmissionSignsExactlyOneCanonicalBodyAndNeverMixesStatus() throws {
        let root = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 11, count: 32))
        let worker = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 12, count: 32))
        var readyFields = try IssuerCBOR.decode(readiness(mode: .admission, siteKeyID: IssuerPhoneWire.sha256(root.publicKey.compressedRepresentation)).canonicalBytes).array(14)
        readyFields[10] = .bytes(IssuerPhoneWire.sha256(worker.publicKey.compressedRepresentation))
        let ready = try IssuerPhoneReadiness(canonicalBytes: IssuerCBOR.array(readyFields).encoded())
        let checkpoint = IssuerCBOR.array([.bytes(Data("ICKP/1".utf8)), .unsigned(0), .bytes(Data(repeating: 0, count: 32)), .unsigned(0), .bytes(Data(repeating: 0, count: 32))])
        let state = IssuerCBOR.array([.bytes(Data("IIST/1".utf8)), .unsigned(1), .bytes(Data()), .bytes(Data(repeating: 1, count: 32)), checkpoint, .bytes(Data(repeating: 2, count: 32)), .bytes(Data(repeating: 3, count: 32)), .bytes(Data("issuer".utf8)), .bytes(Data(repeating: 4, count: 32)), .unsigned(2), .unsigned(0), .unsigned(1)])
        let body = try IssuerCBOR.array([
            .bytes(Data("IADM/1".utf8)), .bytes(ready.authorityID), .bytes(installation), .bytes(ready.siteLabel),
            .bytes(Data("classic-commit-status:mnemosyne/expedition".utf8)),
            .bytes(Data("thesaurophylax.github-exact-source-qualification-credential-projection.v1".utf8)),
            .unsigned(1), .unsigned(1), .bytes(worker.publicKey.compressedRepresentation),
            .bytes(worker.publicKey.compressedRepresentation), .bytes(worker.publicKey.compressedRepresentation),
            checkpoint, state, .bytes(Data(repeating: 9, count: 32)), .bytes(Data(repeating: 1, count: 32)),
            .bytes(Data(repeating: 2, count: 32)), .bytes(Data("lockset".utf8)), .bytes(Data(repeating: 3, count: 32)),
            .bytes(Data("target".utf8)), .bytes(Data(repeating: 4, count: 32)), .unsigned(1),
        ]).encoded()
        let selected = try task(ready, kind: .admission, body: body)
        let start = ContinuousClock().now
        var operation = try IssuerPhoneOperation(readiness: ready, rootAdmissionReference: nil, preparedAt: start)
        try operation.faceAuthenticated(at: start); try operation.arm(at: start)
        try operation.beginSignature(selected, at: start)
        let signed = try root.signature(for: selected.body.signaturePreimage)
        let envelope = try IssuerCheckpointEnvelope.encode(body: selected.body, sitePublicKey: root.publicKey.compressedRepresentation, signature: lowS(signed.rawRepresentation))
        try operation.signatureCompleted(task: selected, envelope: envelope, sitePublicKey: root.publicKey.compressedRepresentation, at: start)
        let terminal = try IssuerCBOR.array([.unsigned(1), .bytes(ready.ceremonyID), .unsigned(0)]).encoded()
        try operation.finish(terminal, at: start)
        XCTAssertThrowsError(try operation.beginSignature(selected, at: start))
        XCTAssertTrue(selected.body.signaturePreimage.starts(with: Data("Mnemosyne/Issuer1482/root-admission/v1\0".utf8)))
        XCTAssertNotEqual(selected.body.signaturePreimage, selected.body.canonicalBytes)
    }

    func testAmbiguousInvocationChangedTaskAndWrongCurrentFactsLock() throws {
        let ready = try readiness(), start = ContinuousClock().now
        let pre = try task(ready, body: status())
        try pre.body.compareCurrentFacts(revocationRevision: 9, keyState: 1)
        XCTAssertThrowsError(try pre.body.compareCurrentFacts(revocationRevision: 10, keyState: 1))
        var operation = try IssuerPhoneOperation(readiness: ready, rootAdmissionReference: Data(repeating: 8, count: 32), preparedAt: start)
        try operation.faceAuthenticated(at: start); try operation.arm(at: start)
        try operation.beginSignature(pre, at: start)
        XCTAssertThrowsError(try operation.beginSignature(pre, at: start))
        XCTAssertThrowsError(try operation.exactCompletedReply(for: pre, at: start))
        XCTAssertThrowsError(try operation.beginSignature(pre, at: start))
    }
}
