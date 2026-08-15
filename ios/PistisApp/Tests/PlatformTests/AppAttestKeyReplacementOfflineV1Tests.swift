import CryptoKit
import Foundation
import XCTest

@testable import Pistis

final class AppAttestKeyReplacementOfflineV1Tests: XCTestCase {
    func testCanonicalPresentationBindsExactMonasFieldsAndMillisExpiry() throws {
        let bytes = try presentation()
        let value = try AppAttestKeyReplacementPresentationV1(
            fileBytes: bytes, nowUnixMillis: 1_001
        )
        XCTAssertEqual(value.wire.transactionID, "01010101-0101-0101-0101-010101010101")
        XCTAssertEqual(value.wire.installationID, "installation-1")
        XCTAssertEqual(value.wire.deviceID, "device-1")
        XCTAssertEqual(value.wire.siteTrustDomain, "site-demo-1")
        XCTAssertEqual(value.oldKeyID, Data(repeating: 2, count: 32))
        XCTAssertEqual(value.wire.oldGeneration, 1)
        XCTAssertEqual(value.wire.newGeneration, 2)

        var changed = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        changed["device_id"] = "device-2"
        let substituted = try AppAttestKeyReplacementPresentationV1(
            fileBytes: try canonicalObject(changed), nowUnixMillis: 1_001
        )
        XCTAssertNotEqual(substituted.digest, value.digest)

        var unknown = changed
        unknown["authority_override"] = "attacker"
        XCTAssertThrowsError(
            try AppAttestKeyReplacementPresentationV1(
                fileBytes: try canonicalObject(unknown), nowUnixMillis: 1_001
            ))
        XCTAssertThrowsError(
            try AppAttestKeyReplacementPresentationV1(
                fileBytes: bytes + Data("\n".utf8), nowUnixMillis: 1_001
            ))
        XCTAssertThrowsError(
            try AppAttestKeyReplacementPresentationV1(
                fileBytes: bytes, nowUnixMillis: 301_001
            ))
    }

    func testApprovalJCSIsByteExactWithMonasContract() throws {
        let approval = AppAttestKeyReplacementApprovalV1(
            wireProtocol: AppAttestKeyReplacementOfflineProfileV1.wireProtocol,
            purpose: AppAttestKeyReplacementOfflineProfileV1.purpose,
            transactionID: "01010101-0101-0101-0101-010101010101",
            installationID: "installation-1",
            deviceID: "device-1",
            siteTrustDomain: "site-demo-1",
            oldKeyIDB64URL: PXARJSON.base64URL(Data(repeating: 2, count: 32)),
            newKeyIDB64URL: PXARJSON.base64URL(Data(repeating: 3, count: 32)),
            attestationSHA256B64URL: PXARJSON.base64URL(Data(repeating: 4, count: 32)),
            challengeB64URL: PXARJSON.base64URL(Data(repeating: 5, count: 32)),
            newGeneration: 2
        )
        let encoded = try PXARJSON.encodeCanonical(approval)
        XCTAssertEqual(
            String(decoding: encoded, as: UTF8.self),
            #"{"attestation_sha256_b64url":"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ","challenge_b64url":"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU","device_id":"device-1","installation_id":"installation-1","new_generation":2,"new_key_id_b64url":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM","old_key_id_b64url":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","protocol":"pistis.apple-app-attest-key-replacement.v1","purpose":"site-root-app-attest-key-replacement","site_trust_domain":"site-demo-1","transaction_id":"01010101-0101-0101-0101-010101010101"}"#
        )
    }

    func testPendingStorageDecodesV1AndRetainsExactV2Submission() throws {
        let transaction = Data(repeating: 1, count: 16)
        let old = Data(repeating: 2, count: 32).base64EncodedString()
        let local = Data(repeating: 4, count: 32).base64EncodedString()
        let replacement = Data(repeating: 3, count: 32).base64EncodedString()
        var legacy = Data("PXAK/v1\0".utf8)
        legacy.append(transaction)
        for field in [old, local, replacement] {
            let bytes = Data(field.utf8)
            legacy.append(UInt8(bytes.count >> 8))
            legacy.append(UInt8(bytes.count & 0xff))
            legacy.append(bytes)
        }
        let decodedLegacy = try KeychainAppleAppAttestReplacementKeyStore.decode(legacy)
        XCTAssertNil(decodedLegacy.canonicalSubmission)

        let submission = try canonicalSubmission()
        let retained = try decodedLegacy.retaining(canonicalSubmission: submission)
        let decodedV2 = try KeychainAppleAppAttestReplacementKeyStore.decode(
            KeychainAppleAppAttestReplacementKeyStore.encode(retained)
        )
        XCTAssertEqual(decodedV2, retained)
        XCTAssertEqual(decodedV2.canonicalSubmission, submission)
    }

    func testReplacementClientStagesFreshKeyWithoutChangingPrimary() async throws {
        let old = Data(repeating: 2, count: 32).base64EncodedString()
        let replacement = Data(repeating: 3, count: 32).base64EncodedString()
        let state = RecordingReplacementStore(primary: old)
        let service = ReplacementAppAttestService(generatedKeyID: replacement)
        let client = AppleAppAttestClient(
            service: service, keyIDStore: state, replacementStore: state
        )
        let transaction = Data(repeating: 1, count: 16)
        let staged = try await client.stageReplacementKey(
            transactionUUID: transaction, expectedCurrentKeyID: old
        ) { key in
            XCTAssertEqual(key, replacement)
            return Data(repeating: 9, count: 32)
        }
        XCTAssertEqual(staged.pending.replacementKeyID, replacement)
        XCTAssertEqual(state.loadKeyID(), old)
        XCTAssertEqual(state.loadPending(), staged.pending)
        XCTAssertEqual(service.attestationHash, Data(repeating: 9, count: 32))

        try state.commitPending(staged.pending)
        XCTAssertEqual(state.loadKeyID(), replacement)
        XCTAssertNil(state.loadPending())
    }

    func testServerOldKeyMismatchStagesWithoutOverwritingLocalPrimary() async throws {
        let serverOld = Data(repeating: 2, count: 32).base64EncodedString()
        let localPrimary = Data(repeating: 4, count: 32).base64EncodedString()
        let replacement = Data(repeating: 3, count: 32).base64EncodedString()
        let state = RecordingReplacementStore(primary: localPrimary)
        let service = ReplacementAppAttestService(generatedKeyID: replacement)
        let client = AppleAppAttestClient(
            service: service, keyIDStore: state, replacementStore: state
        )

        let staged = try await client.stageReplacementKey(
            transactionUUID: Data(repeating: 1, count: 16),
            expectedCurrentKeyID: serverOld,
            clientDataHash: { _ in Data(repeating: 9, count: 32) }
        )

        XCTAssertEqual(staged.pending.expectedCurrentKeyID, serverOld)
        XCTAssertEqual(staged.pending.localPrimaryKeyID, localPrimary)
        XCTAssertEqual(state.loadKeyID(), localPrimary)
        try state.commitPending(staged.pending)
        XCTAssertEqual(state.loadKeyID(), replacement)
    }

    func testPendingTransactionConflictDeniesWithoutGeneration() async throws {
        let old = Data(repeating: 2, count: 32).base64EncodedString()
        let replacement = Data(repeating: 3, count: 32).base64EncodedString()
        let state = RecordingReplacementStore(primary: old)
        state.pending = try PendingAppAttestReplacementKeyV1(
            transactionUUID: Data(repeating: 8, count: 16),
            expectedCurrentKeyID: old,
            localPrimaryKeyID: old,
            replacementKeyID: replacement
        )
        let service = ReplacementAppAttestService(generatedKeyID: replacement)
        let client = AppleAppAttestClient(
            service: service, keyIDStore: state, replacementStore: state
        )
        await assertThrowsErrorAsync {
            _ = try await client.stageReplacementKey(
                transactionUUID: Data(repeating: 1, count: 16),
                expectedCurrentKeyID: old,
                clientDataHash: { _ in Data(repeating: 9, count: 32) }
            )
        }
        XCTAssertEqual(service.generateCount, 0)
    }

    func testExactPendingTransactionResumesWithoutMintingAnotherKey() async throws {
        let old = Data(repeating: 2, count: 32).base64EncodedString()
        let replacement = Data(repeating: 3, count: 32).base64EncodedString()
        let transaction = Data(repeating: 1, count: 16)
        let state = RecordingReplacementStore(primary: old)
        state.pending = try PendingAppAttestReplacementKeyV1(
            transactionUUID: transaction,
            expectedCurrentKeyID: old,
            localPrimaryKeyID: old,
            replacementKeyID: replacement
        )
        let service = ReplacementAppAttestService(
            generatedKeyID: Data(repeating: 4, count: 32).base64EncodedString()
        )
        let client = AppleAppAttestClient(
            service: service, keyIDStore: state, replacementStore: state
        )

        let resumed = try await client.stageReplacementKey(
            transactionUUID: transaction,
            expectedCurrentKeyID: old,
            clientDataHash: { key in
                XCTAssertEqual(key, replacement)
                return Data(repeating: 9, count: 32)
            }
        )

        XCTAssertEqual(resumed.pending, state.pending)
        XCTAssertEqual(service.generateCount, 0)
        XCTAssertEqual(service.attestedKeyID, replacement)
    }

    func testPendingDiscardCannotEraseCommitReconciliationRecord() throws {
        let old = Data(repeating: 2, count: 32).base64EncodedString()
        let replacement = Data(repeating: 3, count: 32).base64EncodedString()
        let transaction = Data(repeating: 1, count: 16)
        let retained = try PendingAppAttestReplacementKeyV1(
            transactionUUID: transaction,
            expectedCurrentKeyID: old,
            localPrimaryKeyID: old,
            replacementKeyID: replacement
        )
        let store = RecordingReplacementStore(primary: replacement)
        store.pending = retained

        XCTAssertThrowsError(try store.discardPending(transactionUUID: transaction))
        XCTAssertEqual(store.pending, retained)
    }

    @MainActor
    func testCoordinatorPromotesOnlyExactCanonicalAcceptedResult() async throws {
        let old = Data(repeating: 2, count: 32).base64EncodedString()
        let replacement = Data(repeating: 3, count: 32).base64EncodedString()
        let pending = try PendingAppAttestReplacementKeyV1(
            transactionUUID: Data(repeating: 1, count: 16),
            expectedCurrentKeyID: old,
            localPrimaryKeyID: old,
            replacementKeyID: replacement
        )
        let committer = RecordingCommitter()
        let submission = try canonicalSubmission()
        let coordinator = AppAttestKeyReplacementCoordinatorV1(
            producer: FixedReplacementProducer(
                pending: pending, canonicalResponse: submission
            ),
            committer: committer
        )
        coordinator.accept(fileBytes: try presentation(), nowUnixMillis: 1_001)
        await coordinator.approve(nowUnixMillis: 1_001)
        XCTAssertEqual(coordinator.phase, .responseReady)

        var wrong = acceptedObject()
        wrong["new_key_id_b64url"] = PXARJSON.base64URL(Data(repeating: 4, count: 32))
        PXARAcceptanceURLProtocol.setResponse(try canonicalObject(wrong))
        let transport = try replacementTransport()
        do {
            _ = try await transport.submitAppAttestReplacement(
                canonicalSubmission: submission
            )
            XCTFail("substituted accepted result unexpectedly authenticated")
        } catch {}
        XCTAssertEqual(coordinator.phase, .responseReady)
        XCTAssertNil(committer.committed)

        PXARAcceptanceURLProtocol.setResponse(try canonicalObject(acceptedObject()))
        let exact = AppAttestKeyReplacementCoordinatorV1(
            producer: FixedReplacementProducer(
                pending: pending, canonicalResponse: submission
            ),
            committer: committer
        )
        exact.accept(fileBytes: try presentation(), nowUnixMillis: 1_001)
        await exact.approve(nowUnixMillis: 1_001)
        await exact.submitAndCommit(using: transport)
        XCTAssertEqual(exact.phase, .accepted)
        XCTAssertEqual(
            committer.committed,
            try pending.retaining(canonicalSubmission: submission)
        )
    }

    @MainActor
    func testLostResponseRelaunchRetriesExactSubmissionAfterPresentationExpiry() async throws {
        let submission = try canonicalSubmission()
        let pending = try PendingAppAttestReplacementKeyV1(
            transactionUUID: Data(repeating: 1, count: 16),
            expectedCurrentKeyID: Data(repeating: 2, count: 32).base64EncodedString(),
            localPrimaryKeyID: Data(repeating: 4, count: 32).base64EncodedString(),
            replacementKeyID: Data(repeating: 3, count: 32).base64EncodedString()
        )
        let committer = RecordingCommitter()
        let first = AppAttestKeyReplacementCoordinatorV1(
            producer: FixedReplacementProducer(
                pending: pending, canonicalResponse: submission
            ),
            committer: committer
        )
        first.accept(fileBytes: try presentation(), nowUnixMillis: 1_001)
        await first.approve(nowUnixMillis: 1_001)
        committer.retained = try pending.retaining(canonicalSubmission: submission)

        let lostTransport = RecordingReplacementTransport()
        await first.submitAndCommit(using: lostTransport)
        XCTAssertEqual(first.phase, .responseReady)
        XCTAssertEqual(first.responseFileBytes, submission)
        XCTAssertNil(committer.committed)
        XCTAssertEqual(lostTransport.submission, submission)

        // At real relaunch time the presentation is expired. Reconciliation
        // still resubmits only the already-generated durable bytes.
        let relaunched = AppAttestKeyReplacementCoordinatorV1(
            producer: FailingReplacementProducer(), committer: committer
        )
        relaunched.restoreRetainedSubmission()
        XCTAssertEqual(relaunched.phase, .responseReady)
        XCTAssertEqual(relaunched.responseFileBytes, submission)

        PXARAcceptanceURLProtocol.setResponse(try canonicalObject(acceptedObject()))
        await relaunched.submitAndCommit(using: try replacementTransport())
        XCTAssertEqual(relaunched.phase, .accepted)
        XCTAssertEqual(committer.committed?.canonicalSubmission, submission)
    }

    @MainActor
    func testAuthenticatedDenialIsTerminalButRetainsExactSubmission() async throws {
        let submission = try canonicalSubmission()
        let pending = try PendingAppAttestReplacementKeyV1(
            transactionUUID: Data(repeating: 1, count: 16),
            expectedCurrentKeyID: Data(repeating: 2, count: 32).base64EncodedString(),
            localPrimaryKeyID: Data(repeating: 4, count: 32).base64EncodedString(),
            replacementKeyID: Data(repeating: 3, count: 32).base64EncodedString()
        )
        let committer = RecordingCommitter()
        let coordinator = AppAttestKeyReplacementCoordinatorV1(
            producer: FixedReplacementProducer(
                pending: pending, canonicalResponse: submission
            ),
            committer: committer
        )
        coordinator.accept(fileBytes: try presentation(), nowUnixMillis: 1_001)
        await coordinator.approve(nowUnixMillis: 1_001)
        committer.retained = try pending.retaining(canonicalSubmission: submission)

        PXARAcceptanceURLProtocol.setStatus(410)
        await coordinator.submitAndCommit(using: try replacementTransport())
        XCTAssertEqual(coordinator.phase, .failed)
        XCTAssertEqual(coordinator.responseFileBytes, submission)
        XCTAssertEqual(committer.retained?.canonicalSubmission, submission)
        XCTAssertNil(committer.committed)
    }

    private func presentation() throws -> Data {
        let approval = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 7, count: 32)
        ).publicKey.compressedRepresentation
        let wire = AppAttestKeyReplacementPresentationWireV1(
            wireProtocol: AppAttestKeyReplacementOfflineProfileV1.wireProtocol,
            purpose: AppAttestKeyReplacementOfflineProfileV1.purpose,
            transactionID: "01010101-0101-0101-0101-010101010101",
            installationID: "installation-1",
            deviceID: "device-1",
            siteTrustDomain: "site-demo-1",
            oldKeyIDB64URL: PXARJSON.base64URL(Data(repeating: 2, count: 32)),
            oldGeneration: 1,
            newGeneration: 2,
            challengeB64URL: PXARJSON.base64URL(Data(repeating: 8, count: 32)),
            siteRootKeyID: "site-root-1",
            siteRootPublicKeySEC1B64URL: PXARJSON.base64URL(approval),
            issuedAtUnixMillis: 1_000,
            expiresAtUnixMillis: 301_000
        )
        return try PXARJSON.encodeCanonical(wire)
    }

    private func acceptedObject() -> [String: Any] {
        [
            "protocol": AppAttestKeyReplacementOfflineProfileV1.wireProtocol,
            "transaction_id": "01010101-0101-0101-0101-010101010101",
            "installation_id": "installation-1",
            "old_generation": 1,
            "new_generation": 2,
            "old_key_id_b64url": PXARJSON.base64URL(Data(repeating: 2, count: 32)),
            "new_key_id_b64url": PXARJSON.base64URL(Data(repeating: 3, count: 32)),
            "state": "accepted",
        ]
    }

    private func canonicalSubmission() throws -> Data {
        let parsed = try AppAttestKeyReplacementPresentationV1(
            fileBytes: presentation(), nowUnixMillis: 1_001
        )
        let attestation = Data(repeating: 6, count: 64)
        let newKey = PXARJSON.base64URL(Data(repeating: 3, count: 32))
        let approval = AppAttestKeyReplacementApprovalV1(
            wireProtocol: AppAttestKeyReplacementOfflineProfileV1.wireProtocol,
            purpose: AppAttestKeyReplacementOfflineProfileV1.purpose,
            transactionID: parsed.wire.transactionID,
            installationID: parsed.wire.installationID,
            deviceID: parsed.wire.deviceID,
            siteTrustDomain: parsed.wire.siteTrustDomain,
            oldKeyIDB64URL: parsed.wire.oldKeyIDB64URL,
            newKeyIDB64URL: newKey,
            attestationSHA256B64URL: PXARJSON.base64URL(
                Data(SHA256.hash(data: attestation))
            ),
            challengeB64URL: parsed.wire.challengeB64URL,
            newGeneration: parsed.wire.newGeneration
        )
        let registration = try AppleAppAttestRegistrationEnvelope(
            ceremonyID: parsed.wire.transactionID,
            siteTrustDomain: parsed.wire.siteTrustDomain,
            appleKeyID: Data(repeating: 3, count: 32).base64EncodedString(),
            clientDataHash: parsed.challenge,
            attestationObject: attestation
        )
        return try PXARJSON.encodeCanonical(
            AppAttestKeyReplacementSubmissionV1(
                wireProtocol: AppAttestKeyReplacementOfflineProfileV1.wireProtocol,
                presentation: parsed.wire,
                appleRegistration: registration,
                approval: approval,
                siteRootSignatureB64URL: PXARJSON.base64URL(Data(repeating: 7, count: 64))
            ))
    }

    private func replacementTransport() throws -> MonasAppAttestTransport {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [PXARAcceptanceURLProtocol.self]
        return try MonasAppAttestTransport(
            authorityOrigin: XCTUnwrap(URL(string: "https://monas.example.test")),
            expectedSPKISHA256: Data(repeating: 9, count: 32),
            configuration: configuration
        )
    }

    private func canonicalObject(_ value: [String: Any]) throws -> Data {
        try JSONSerialization.data(
            withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]
        )
    }
}

private final class RecordingReplacementStore:
    AppleAppAttestKeyIDStoring, AppleAppAttestReplacementKeyStoring, @unchecked Sendable
{
    private(set) var primary: String
    var pending: PendingAppAttestReplacementKeyV1?
    init(primary: String) { self.primary = primary }
    func loadKeyID() -> String? { primary }
    func saveKeyID(_ keyID: String) throws { primary = keyID }
    func loadPending() -> PendingAppAttestReplacementKeyV1? { pending }
    func savePending(_ value: PendingAppAttestReplacementKeyV1) throws {
        if let pending, pending != value {
            guard pending.transactionUUID == value.transactionUUID,
                pending.expectedCurrentKeyID == value.expectedCurrentKeyID,
                pending.localPrimaryKeyID == value.localPrimaryKeyID,
                pending.replacementKeyID == value.replacementKeyID,
                pending.canonicalSubmission == nil,
                value.canonicalSubmission != nil
            else { throw PlatformFailure.appAttestInvalidInput }
        }
        pending = value
    }
    func commitPending(_ value: PendingAppAttestReplacementKeyV1) throws {
        guard pending == value,
            primary == value.localPrimaryKeyID || primary == value.replacementKeyID
        else { throw PlatformFailure.appAttestInvalidInput }
        primary = value.replacementKeyID
        pending = nil
    }
    func discardPending(transactionUUID: Data) throws {
        guard let retained = pending,
            retained.transactionUUID == transactionUUID,
            primary == retained.localPrimaryKeyID
        else { throw PlatformFailure.appAttestInvalidInput }
        pending = nil
    }
}

private final class ReplacementAppAttestService: AppleAppAttestServicing, @unchecked Sendable {
    let generatedKeyID: String
    private(set) var generateCount = 0
    private(set) var attestationHash: Data?
    private(set) var attestedKeyID: String?
    init(generatedKeyID: String) { self.generatedKeyID = generatedKeyID }
    var isSupported: Bool { true }
    func generateKey() async throws -> String {
        generateCount += 1
        return generatedKeyID
    }
    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
        attestedKeyID = keyID
        attestationHash = clientDataHash
        return Data(repeating: 6, count: 64)
    }
    func generateAssertion(_: String, clientDataHash _: Data) async throws -> Data { Data() }
}

private struct FixedReplacementProducer: AppAttestKeyReplacementProducingV1 {
    let pending: PendingAppAttestReplacementKeyV1
    let canonicalResponse: Data
    func produce(
        _: AppAttestKeyReplacementPresentationV1, nowUnixMillis _: UInt64
    ) async throws -> StagedAppAttestKeyReplacementResponseV1 {
        StagedAppAttestKeyReplacementResponseV1(
            canonicalResponse: canonicalResponse,
            pendingKey: try pending.retaining(canonicalSubmission: canonicalResponse)
        )
    }
}

private struct FailingReplacementProducer: AppAttestKeyReplacementProducingV1 {
    func produce(
        _: AppAttestKeyReplacementPresentationV1, nowUnixMillis _: UInt64
    ) async throws -> StagedAppAttestKeyReplacementResponseV1 {
        throw PlatformFailure.appAttestInvalidInput
    }
}

private final class RecordingCommitter:
    AppAttestKeyReplacementCommittingV1, @unchecked Sendable
{
    var committed: PendingAppAttestReplacementKeyV1?
    var retained: PendingAppAttestReplacementKeyV1?
    func loadRetainedReplacement() -> PendingAppAttestReplacementKeyV1? { retained }
    func commitReplacementKey(
        _ pending: PendingAppAttestReplacementKeyV1,
        authenticated _: AuthenticatedAppAttestReplacementAcceptanceV1
    ) throws {
        committed = pending
    }
    func discardReplacementKey(transactionUUID _: Data) throws {}
}

private final class RecordingReplacementTransport:
    AppAttestReplacementSubmittingV1, @unchecked Sendable
{
    private let lock = NSLock()
    private var recorded: Data?
    var submission: Data? {
        lock.withLock { recorded }
    }
    func submitAppAttestReplacement(
        canonicalSubmission: Data
    ) async throws -> AuthenticatedAppAttestReplacementAcceptanceV1 {
        lock.withLock { recorded = canonicalSubmission }
        throw AppAttestReplacementTransportFailure.ambiguousDelivery
    }
}

private final class PXARAcceptanceURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var responseData = Data()
    nonisolated(unsafe) private static var statusCode = 200

    static func setResponse(_ data: Data) {
        lock.lock()
        responseData = data
        statusCode = 200
        lock.unlock()
    }

    static func setStatus(_ value: Int) {
        lock.lock()
        statusCode = value
        lock.unlock()
    }

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        let data = Self.responseData
        let statusCode = Self.statusCode
        Self.lock.unlock()
        let response = HTTPURLResponse(
            url: request.url!, statusCode: statusCode, httpVersion: "HTTP/1.1",
            headerFields: ["Cache-Control": "no-store"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}

}

private func assertThrowsErrorAsync(
    _ expression: () async throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        try await expression()
        XCTFail("expression unexpectedly succeeded", file: file, line: line)
    } catch {}
}
