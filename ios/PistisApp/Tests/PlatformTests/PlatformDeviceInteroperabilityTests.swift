import Foundation
import LocalAuthentication
import XCTest
@testable import Pistis

final class PlatformDeviceInteroperabilityTests: XCTestCase {
    func testPinnedSigningInputFixtureIsUsable() throws {
        let harness = try DeviceInteroperabilityHarness.fixture(from: Bundle(for: Self.self))
        XCTAssertEqual(harness.signatureStructure.count, 320)
    }

    func testRecordDerivesKeyIDAndRejectsHighS() throws {
        let publicKey = DevicePublicKey(
            compressedSEC1: Data([
                0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
                0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
                0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
                0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
                0x96,
            ]),
            assurance: .secureEnclaveFaceIDCurrentSet
        )
        let signature = Data([1] + Array(repeating: 0, count: 31)
            + Array(repeating: 0, count: 31) + [1])
        let record = try DeviceInteroperabilityRecord(
            publicKey: publicKey,
            signatureStructure: Data([0xa0]),
            rawES256Signature: signature
        )

        XCTAssertEqual(
            record.keyIDHex,
            "7ad63df38de8c402c7259db7bbc1b97b6890ffaa0a4adf78bc2b873efcabbf8d"
        )
        XCTAssertEqual(record.signatureStructureSHA256Hex.count, 64)
        XCTAssertEqual(record.rawES256SignatureHex, signature.map { String(format: "%02x", $0) }.joined())

        var highS = signature
        highS.replaceSubrange(32 ..< 64, with: Data(repeating: 0xff, count: 32))
        XCTAssertThrowsError(
            try DeviceInteroperabilityRecord(
                publicKey: publicKey,
                signatureStructure: Data([0xa0]),
                rawES256Signature: highS
            )
        )
    }

    func testPhysicalCeremonyRequiresFaceIDRatherThanGenericBiometrics() {
        XCTAssertTrue(SecureEnclaveSigner.isFaceID(.faceID))
        XCTAssertFalse(SecureEnclaveSigner.isFaceID(.touchID))
        XCTAssertFalse(SecureEnclaveSigner.isFaceID(.none))
    }

    #if targetEnvironment(simulator)
    func testPhysicalDeviceHarnessFailsClosedOnSimulator() throws {
        let harness = try DeviceInteroperabilityHarness.fixture(from: Bundle(for: Self.self))
        XCTAssertThrowsError(try harness.observe())
    }
    #else
    func testPhysicalDeviceInteroperabilityCeremony() throws {
        guard ProcessInfo.processInfo.environment["PISTIS_RUN_PHYSICAL_INTEROPERABILITY"] == "1" else {
            throw XCTSkip("Set PISTIS_RUN_PHYSICAL_INTEROPERABILITY=1 for the reviewed physical-device ceremony.")
        }

        let harness = try DeviceInteroperabilityHarness.fixture(from: Bundle(for: Self.self))
        let record = try harness.observe()
        let attachment = XCTAttachment(string: try record.renderedJSON())
        attachment.name = "pistis-epic18-non-secret-interoperability-observation.json"
        attachment.lifetime = .keepAlways
        add(attachment)
    }
    #endif
}
