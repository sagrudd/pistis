import Crypto
import Foundation
@testable import PistisCore
import Testing

private struct ContinuityTestFixture: Sendable {
    let value: [String: String]
    let keys, authority, generationHex: [String]
    init() throws {
        let url = Bundle.module.url(forResource: "public-extension", withExtension: "json",
                                    subdirectory: "ContinuityApprovalFixtures")!
        let raw = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        value = raw.compactMapValues { $0 as? String }
        keys = raw["keys"] as! [String]; authority = raw["authority"] as! [String]
        generationHex = raw["generations"] as! [String]
    }
    func bytes(_ key: String) -> Data { continuityHex(value[key]!) }
    var key: Data { continuityHex(keys[0]) }
    var generations: [Data] { generationHex.map(continuityHex) }
    func body(_ key: String) throws -> Data { try ContinuityValue.decode(bytes(key)).fields(3)[0].encoded }
    var issuer: Data { continuityHex(authority[0]) }
    func presentation() throws -> ValidatedContinuityPresentation {
        try .decode(allocationBytes: bytes("allocation"), descriptorBytes: body("descriptor"),
                    generationRecords: generations, expectedApprovalPublicKey: key, excludedPublicKeys: [])
    }
}

@Test func continuityOriginalR3SignaturesAndExactDAGAreConsumed() throws {
    let f = try ContinuityTestFixture(), p = try f.presentation()
    #expect(p.allocation.successorCap <= 5)
    #expect(try p.verifySelection(f.bytes("selection"), signedDescriptor: f.bytes("descriptor")).count == 32)
    try p.verifyIssuer(f.issuer, signedDescriptor: f.bytes("descriptor"), signedSelection: f.bytes("selection"))
    #expect(p.allocation.scope.privateIPs == ["10.0.0.8"])
}

@Test func continuityUnknownProfileArityCapAndNoncanonicalInputsReject() throws {
    let f = try ContinuityTestFixture()
    var allocation = try ContinuityValue.decode(f.bytes("allocation")).fields(27)
    for (index, replacement) in [(1, ContinuityValue.bytes(Data(repeating: 0, count: 32))),
                                  (25, .uint(6)), (18, .uint(0)), (16, .bytes(Data(repeating: 1, count: 32)))] {
        var bad = allocation; bad[index] = replacement
        #expect(throws: ContinuityApprovalError.self) { try ContinuityAllocation(.array(bad)) }
    }
    allocation.append(.uint(0))
    #expect(throws: ContinuityApprovalError.self) { try ContinuityAllocation(.array(allocation)) }
    for bytes in [Data([0x9f, 0xff]), Data([0x81, 0x18, 0x01]), Data([0xa0]), Data([0x80, 0])] {
        #expect(throws: ContinuityApprovalError.self) { try ContinuityValue.decode(bytes) }
    }
}

@Test func continuitySignatureDomainKeyHighSAndContextSubstitutionReject() throws {
    let f = try ContinuityTestFixture(), p = try f.presentation()
    var envelope = try ContinuityValue.decode(f.bytes("selection")).fields(3)
    envelope[2] = .bytes(Data(repeating: 0xff, count: 64))
    #expect(throws: ContinuityApprovalError.self) { try p.verifySelection(ContinuityValue.array(envelope).encoded, signedDescriptor: f.bytes("descriptor")) }
    let original = try ContinuityValue.decode(f.bytes("selection")).fields(3)
    var tampered = original
    var tamperedBody = try original[0].fields(18)
    tamperedBody[13] = .bytes(Data(repeating: 1, count: 32))
    tampered[0] = .array(tamperedBody)
    #expect(throws: ContinuityApprovalError.self) {
        try p.verifySelection(ContinuityValue.array(tampered).encoded, signedDescriptor: f.bytes("descriptor"))
    }
    #expect(throws: ContinuityApprovalError.self) {
        try continuityKeyID(Data([2]) + Data(repeating: 0xff, count: 32))
    }
    let signature = try original[2].data(64)
    let order = Array(continuityHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"))
    let scalar = Array(signature.suffix(32))
    var high = [UInt8](repeating: 0, count: 32), borrow = 0
    for index in (0..<32).reversed() {
        let difference = Int(order[index]) - Int(scalar[index]) - borrow
        high[index] = UInt8(truncatingIfNeeded: difference)
        borrow = difference < 0 ? 1 : 0
    }
    var highEnvelope = original
    highEnvelope[2] = .bytes(Data(signature.prefix(32)) + Data(high))
    #expect(!ContinuitySignedEnvelope.lowS(Data(signature.prefix(32)) + Data(high)))
    #expect(throws: ContinuityApprovalError.self) {
        try p.verifySelection(ContinuityValue.array(highEnvelope).encoded, signedDescriptor: f.bytes("descriptor"))
    }
    var body = try ContinuityValue.decode(try f.body("selection")).fields(18)
    body[2] = .bytes(Data(repeating: 0, count: 32))
    #expect(throws: ContinuityApprovalError.self) { try p.selectionBody(ContinuityValue.array(body).encoded, signedDescriptor: f.bytes("descriptor")) }
    #expect(throws: ContinuityApprovalError.self) { try ContinuitySignedEnvelope(f.bytes("descriptor"), kind: .issuer, publicKey: f.key) }
    let wrong = continuityHex(f.keys[1])
    #expect(throws: ContinuityApprovalError.self) { try ContinuitySignedEnvelope(f.bytes("descriptor"), kind: .descriptor, publicKey: wrong) }
    #expect(throws: CoseSign1Error.self) { try CoseSign1.decode(f.bytes("descriptor")) }
}

private struct FixtureClock: ContinuityApprovalClock {
    let now: UInt64
    func seconds() -> UInt64 { now }
}
private actor ModelAuthority: ContinuityCurrentAuthority {
    var calls = 0
    var denyAt: Int?
    init(denyAt: Int? = nil) { self.denyAt = denyAt }
    func revalidate(_ kind: ContinuityApprovalKind, presentation: ValidatedContinuityPresentation,
                    exactBodyDigest: Data) throws {
        calls += 1
        guard denyAt != calls else { throw ContinuityApprovalError.unavailableEnrollment }
        // Explicit TEST model, not a production generation/status verifier.
        guard presentation.generationRecords.count == 4, exactBodyDigest.count == 32 else {
            throw ContinuityApprovalError.generation
        }
    }
}
private actor ModelDriver: ContinuityPhoneDriver {
    var calls = 0
    let fixture: ContinuityTestFixture
    let fail: Bool
    init(_ fixture: ContinuityTestFixture, fail: Bool = false) { self.fixture = fixture; self.fail = fail }
    func result(_ key: String) throws -> Data {
        calls += 1
        if fail { throw ContinuityApprovalError.signature }
        return try ContinuityValue.decode(fixture.bytes(key)).fields(3)[2].data(64)
    }
    func attestDescriptor(_ presentation: ValidatedContinuityPresentation) throws -> Data { try result("descriptor") }
    func selectContinuityMode(_ presentation: ValidatedContinuityPresentation, selection: ContinuityValue) throws -> Data { try result("selection") }
    func attestIssuer(_ presentation: ValidatedContinuityPresentation, issuer: ContinuityValue) throws -> Data {
        calls += 1
        return try ContinuityValue.decode(fixture.issuer).fields(3)[2].data(64)
    }
}
private actor ModelLedger: ContinuityApprovalLedger {
    var records: [ContinuityOperationIdentity: ContinuityRetainedOperation] = [:]
    let failRetention: Bool
    init(failRetention: Bool = false, records: [ContinuityOperationIdentity: ContinuityRetainedOperation] = [:]) {
        self.failRetention = failRetention; self.records = records
    }
    func snapshot() -> [ContinuityOperationIdentity: ContinuityRetainedOperation] { records }
    func read(_ id: ContinuityOperationIdentity) -> ContinuityRetainedOperation? { records[id] }
    func reserve(_ id: ContinuityOperationIdentity, exactBody: Data) throws -> ContinuityRetainedOperation {
        if let record = records[id] {
            guard record.body == exactBody else { throw ContinuityApprovalError.conflict }
            return record
        }
        let record = ContinuityRetainedOperation(identity: id, body: exactBody, phase: .preparedNoKeyInvocation, envelope: nil)
        records[id] = record; return record
    }
    func transition(_ id: ContinuityOperationIdentity, body: Data, from: ContinuityOperationPhase,
                    to: ContinuityOperationPhase, envelope: Data? = nil) throws {
        guard let old = records[id], old.body == body, old.phase == from else { throw ContinuityApprovalError.conflict }
        records[id] = ContinuityRetainedOperation(identity: id, body: body, phase: to, envelope: envelope)
    }
    func fence(_ id: ContinuityOperationIdentity, exactBody: Data) throws { try transition(id, body: exactBody, from: .preparedNoKeyInvocation, to: .dispatchFenced) }
    func neverInvoked(_ id: ContinuityOperationIdentity, exactBody: Data) throws { try transition(id, body: exactBody, from: .dispatchFenced, to: .terminalProvenUnsigned) }
    func retain(_ id: ContinuityOperationIdentity, exactBody: Data, envelope: Data) throws {
        if failRetention { throw ContinuityApprovalError.retentionFailure }
        try transition(id, body: exactBody, from: .dispatchFenced, to: .signedRetained, envelope: envelope)
    }
    func unresolved(_ id: ContinuityOperationIdentity, exactBody: Data) throws { try transition(id, body: exactBody, from: .dispatchFenced, to: .unresolved) }
}

@Test func continuityClosedProducerOrderAndExactRetryNeverResign() async throws {
    let f = try ContinuityTestFixture(), p = try f.presentation()
    let driver = ModelDriver(f), ledger = ModelLedger()
    let producer = ContinuityApprovalProducer(authority: ModelAuthority(), driver: driver, ledger: ledger,
        clock: FixtureClock(now: [p.descriptor.interval.notBefore, p.allocation.grantInterval.notBefore].max()! + 1))
    await #expect(throws: ContinuityApprovalError.self) { try await producer.attestIssuer(p) }
    let descriptor = try await producer.attestDescriptor(p)
    #expect(descriptor == f.bytes("descriptor"))
    #expect(try await producer.attestDescriptor(p) == descriptor)
    let selection = try await producer.selectContinuityMode(p, canonicalSelection: f.body("selection"))
    #expect(selection == f.bytes("selection"))
    let issuer = try await producer.attestIssuer(p)
    #expect(issuer == f.issuer)
    #expect(try await producer.attestIssuer(p) == issuer)
    #expect(await driver.calls == 3)
}

@Test func continuityRevocationBeforeInvocationAndAmbiguousResultAreTerminal() async throws {
    let f = try ContinuityTestFixture(), p = try f.presentation()
    for (denyAt, fail, retention) in [(2 as Int?, false, false), (nil, true, false), (nil, false, true)] {
        let driver = ModelDriver(f, fail: fail), ledger = ModelLedger(failRetention: retention)
        let producer = ContinuityApprovalProducer(authority: ModelAuthority(denyAt: denyAt), driver: driver,
            ledger: ledger, clock: FixtureClock(now: [p.descriptor.interval.notBefore, p.allocation.grantInterval.notBefore].max()! + 1))
        await #expect(throws: ContinuityApprovalError.self) { try await producer.attestDescriptor(p) }
        await #expect(throws: ContinuityApprovalError.self) { try await producer.attestDescriptor(p) }
        #expect(await driver.calls == (denyAt == nil ? 1 : 0))
    }
}

@Test func continuityPublicDefaultCannotCreateEnrolmentOrSign() async throws {
    let p = try ContinuityTestFixture().presentation()
    let producer = ContinuityApprovalProducer()
    await #expect(throws: ContinuityApprovalError.unavailableEnrollment) { try await producer.attestDescriptor(p) }
}

// Restart models copy persisted records; they do not claim a protected native store.
@Test func continuityRestartPreservesExactResultAndAmbiguousFence() async throws {
    let f = try ContinuityTestFixture(), p = try f.presentation()
    let clock = FixtureClock(now: p.allocation.grantInterval.notBefore + 1)
    let firstLedger = ModelLedger(), firstDriver = ModelDriver(f)
    let first = ContinuityApprovalProducer(authority: ModelAuthority(), driver: firstDriver,
                                           ledger: firstLedger, clock: clock)
    let signed = try await first.attestDescriptor(p)
    let restored = ModelLedger(records: await firstLedger.snapshot()), restoredDriver = ModelDriver(f)
    let restarted = ContinuityApprovalProducer(authority: ModelAuthority(), driver: restoredDriver,
                                               ledger: restored, clock: clock)
    #expect(try await restarted.attestDescriptor(p) == signed)
    #expect(await restoredDriver.calls == 0)
    let id = ContinuityOperationIdentity(operation: p.allocation.operation, kind: .descriptor)
    for phase in [ContinuityOperationPhase.dispatchFenced, .unresolved] {
        let record = ContinuityRetainedOperation(identity: id, body: p.descriptor.value.encoded,
                                                phase: phase, envelope: nil)
        let driver = ModelDriver(f)
        let producer = ContinuityApprovalProducer(authority: ModelAuthority(), driver: driver,
            ledger: ModelLedger(records: [id: record]), clock: clock)
        await #expect(throws: ContinuityApprovalError.ambiguousInvocation) { try await producer.attestDescriptor(p) }
        #expect(await driver.calls == 0)
    }
}

@Test func continuityIdentityConflictExpiryAndRevocationPreventInvocation() async throws {
    let f = try ContinuityTestFixture(), p = try f.presentation()
    let id = ContinuityOperationIdentity(operation: p.allocation.operation, kind: .descriptor)
    let ledger = ModelLedger()
    _ = try await ledger.reserve(id, exactBody: p.descriptor.value.encoded)
    await #expect(throws: ContinuityApprovalError.conflict) {
        try await ledger.reserve(id, exactBody: Data([0x80]))
    }
    for (authority, now) in [(ModelAuthority(denyAt: 1), p.allocation.grantInterval.notBefore + 1),
                              (ModelAuthority(), p.descriptor.interval.notAfter + 1)] {
        let driver = ModelDriver(f), empty = ModelLedger()
        let producer = ContinuityApprovalProducer(authority: authority, driver: driver, ledger: empty,
                                                   clock: FixtureClock(now: now))
        await #expect(throws: ContinuityApprovalError.self) { try await producer.attestDescriptor(p) }
        #expect(await driver.calls == 0)
        #expect(await empty.snapshot().isEmpty)
    }
}

@Test func continuityCancellationBeforeReservationCannotInvoke() async throws {
    let f = try ContinuityTestFixture(), p = try f.presentation()
    let driver = ModelDriver(f), ledger = ModelLedger()
    let producer = ContinuityApprovalProducer(authority: ModelAuthority(), driver: driver, ledger: ledger,
        clock: FixtureClock(now: p.allocation.grantInterval.notBefore + 1))
    let task = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        _ = try await producer.attestDescriptor(p)
    }
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(await driver.calls == 0)
    #expect(await ledger.snapshot().isEmpty)
}

@Test func continuityAllocationCapacityBoundariesAreFactsOnly() throws {
    let f = try ContinuityTestFixture()
    let original = try ContinuityValue.decode(f.bytes("allocation")).fields(27)
    for cap in [UInt64(0), UInt64(5)] {
        var fields = original; fields[25] = .uint(cap)
        #expect(try ContinuityAllocation(.array(fields)).successorCap == cap)
    }
}

@Test func continuityCanonicalArrayCountAndDepthBoundaries() throws {
    let hundred = ContinuityValue.array(Array(repeating: .uint(0), count: 100)).encoded
    #expect(try ContinuityValue.decode(hundred).encoded == hundred)
    let hundredOne = ContinuityValue.array(Array(repeating: .uint(0), count: 101)).encoded
    #expect(throws: ContinuityApprovalError.bound) { try ContinuityValue.decode(hundredOne) }
    let sixteen = Data(repeating: 0x81, count: 15) + Data([0x80])
    #expect(try ContinuityValue.decode(sixteen).encoded == sixteen)
    let seventeen = Data([0x81]) + sixteen
    #expect(throws: ContinuityApprovalError.bound) { try ContinuityValue.decode(seventeen) }
    let siblings = ContinuityValue.array([.array([]), .array([.array([])]), .uint(1)]).encoded
    #expect(try ContinuityValue.decode(siblings).encoded == siblings)
}

// TEST clock advances across the async admission/reservation/fence boundaries.
private final class AdvancingFixtureClock: ContinuityApprovalClock, @unchecked Sendable {
    private let lock = NSLock()
    private let values: [UInt64]
    private var index = 0
    init(_ values: [UInt64]) { self.values = values }
    func seconds() -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        let value = values[min(index, values.count - 1)]
        index += 1
        return value
    }
}

@Test func continuitySelectionExpiryDuringAdmissionOrFencingNeverInvokes() async throws {
    let f = try ContinuityTestFixture(), p = try f.presentation()
    let now = p.allocation.grantInterval.notBefore + 1
    for times in [[now, now + 2], [now, now, now + 2]] {
        let ledger = ModelLedger()
        let setup = ContinuityApprovalProducer(authority: ModelAuthority(), driver: ModelDriver(f),
                                               ledger: ledger, clock: FixtureClock(now: now))
        _ = try await setup.attestDescriptor(p)
        var fields = try ContinuityValue.decode(try f.body("selection")).fields(18)
        fields[16] = .uint(now); fields[17] = .uint(now + 2)
        let driver = ModelDriver(f)
        let producer = ContinuityApprovalProducer(authority: ModelAuthority(), driver: driver,
            ledger: ledger, clock: AdvancingFixtureClock(times))
        await #expect(throws: ContinuityApprovalError.expired) {
            try await producer.selectContinuityMode(p, canonicalSelection: ContinuityValue.array(fields).encoded)
        }
        #expect(await driver.calls == 0)
        let id = ContinuityOperationIdentity(operation: p.allocation.operation, kind: .selection)
        if times.count == 3 {
            #expect(await ledger.read(id)?.phase == .terminalProvenUnsigned)
        } else {
            #expect(await ledger.read(id) == nil)
        }
    }
}

// Fresh ephemeral TEST software key only; no enrolled credential or stored key.
@Test func continuityIssuerExpiryAcrossFenceDoesNotInvokeWithHistoricalSelection() async throws {
    let f = try ContinuityTestFixture(), original = try f.presentation()
    let now = original.allocation.grantInterval.notBefore + 1
    let key = P256.Signing.PrivateKey()
    let publicKey = key.publicKey.compressedRepresentation
    let keyID = try continuityKeyID(publicKey)
    var descriptorFields = try original.descriptor.value.fields(21)
    descriptorFields[16] = .bytes(keyID)
    let descriptorBody = ContinuityValue.array(descriptorFields)
    let p = try ValidatedContinuityPresentation.decode(allocationBytes: f.bytes("allocation"),
        descriptorBytes: descriptorBody.encoded, generationRecords: f.generations,
        expectedApprovalPublicKey: publicKey, excludedPublicKeys: [])

    // Reviewed SwiftCrypto does the signing. Scalar subtraction only chooses the
    // mathematically equivalent canonical low-S encoding for these TEST objects.
    func signedTestObject(_ body: ContinuityValue, kind: ContinuityApprovalKind) throws -> Data {
        let prehash = SHA256.hash(data: Data(kind.signatureDomain.utf8) + Data([0]) + body.encoded)
        var signature = try key.signature(for: prehash).rawRepresentation
        if !ContinuitySignedEnvelope.lowS(signature) {
            let order = Array(continuityHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"))
            let scalar = Array(signature.suffix(32))
            var low = [UInt8](repeating: 0, count: 32), borrow = 0
            for index in (0..<32).reversed() {
                let difference = Int(order[index]) - Int(scalar[index]) - borrow
                low[index] = UInt8(truncatingIfNeeded: difference)
                borrow = difference < 0 ? 1 : 0
            }
            signature = Data(signature.prefix(32)) + Data(low)
        }
        return ContinuityValue.array([body, .bytes(keyID), .bytes(signature)]).encoded
    }
    let descriptor = try signedTestObject(descriptorBody, kind: .descriptor)
    _ = try p.descriptorEnvelope(descriptor)
    var selectionFields = try ContinuityValue.decode(try f.body("selection")).fields(18)
    selectionFields[5] = .bytes(p.descriptor.digest)
    selectionFields[6] = .bytes(continuityDigest("Mnemosyne/Proxenos/continuity-enrollment-origin/v1", descriptor))
    selectionFields[15] = .bytes(keyID)
    selectionFields[16] = .uint(now); selectionFields[17] = .uint(now + 2)
    let selectionBody = ContinuityValue.array(selectionFields)
    let selection = try signedTestObject(selectionBody, kind: .selection)
    _ = try p.verifySelection(selection, signedDescriptor: descriptor)
    #expect(p.current(now + 2)) // Isolates PCMS expiry: all other intervals stay current.
    let descriptorID = ContinuityOperationIdentity(operation: p.allocation.operation, kind: .descriptor)
    let selectionID = ContinuityOperationIdentity(operation: p.allocation.operation, kind: .selection)
    let ledger = ModelLedger(records: [
        descriptorID: ContinuityRetainedOperation(identity: descriptorID, body: descriptorBody.encoded,
            phase: .signedRetained, envelope: descriptor),
        selectionID: ContinuityRetainedOperation(identity: selectionID, body: selectionBody.encoded,
            phase: .signedRetained, envelope: selection)
    ])
    let driver = ModelDriver(f)
    let producer = ContinuityApprovalProducer(authority: ModelAuthority(), driver: driver, ledger: ledger,
                                               clock: AdvancingFixtureClock([now, now, now + 2]))
    await #expect(throws: ContinuityApprovalError.expired) { try await producer.attestIssuer(p) }
    #expect(await driver.calls == 0)
    let id = ContinuityOperationIdentity(operation: p.allocation.operation, kind: .issuer)
    #expect(await ledger.read(id)?.phase == .terminalProvenUnsigned)
}
