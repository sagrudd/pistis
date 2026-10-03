import CryptoKit
import Darwin
import XCTest

@testable import Pistis

final class SiteX509OfflineCustodyV2Tests: XCTestCase {
    func testSingleDescriptorImportRejectsSubstitutedSymlinkAndFIFO() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let selected = directory.appendingPathComponent("selected.json")
        let original = directory.appendingPathComponent("original.json")
        let bytes = try CustodyFixture().data()
        try bytes.write(to: selected)
        try bytes.write(to: original)
        XCTAssertEqual(try SiteX509OfflineCustodyV2.readRegularFile(selected), bytes)
        let metadata = try selected.resourceValues(forKeys: [.isRegularFileKey])
        XCTAssertEqual(metadata.isRegularFile, true)
        try FileManager.default.removeItem(at: selected)
        try FileManager.default.createSymbolicLink(at: selected, withDestinationURL: original)
        XCTAssertThrowsError(try SiteX509OfflineCustodyV2.readRegularFile(selected))
        try FileManager.default.removeItem(at: selected)
        XCTAssertEqual(mkfifo(selected.path, S_IRUSR | S_IWUSR), 0)
        XCTAssertThrowsError(try SiteX509OfflineCustodyV2.readRegularFile(selected))
        XCTAssertEqual(try Data(contentsOf: original), bytes)
    }

    func testSingleDescriptorImportRejectsDirectoryEmptyAndOversizedFiles() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        XCTAssertThrowsError(try SiteX509OfflineCustodyV2.readRegularFile(directory))
        let selected = directory.appendingPathComponent("selected.json")
        try Data().write(to: selected)
        XCTAssertThrowsError(try SiteX509OfflineCustodyV2.readRegularFile(selected))
        try Data(repeating: 0, count: SiteX509OfflineCustodyV2.maximumFileBytes + 1).write(to: selected)
        XCTAssertThrowsError(try SiteX509OfflineCustodyV2.readRegularFile(selected))
    }

    func testBothRolesUseCompleteIndependentDigestAndEnrolledRootHash() throws {
        for role in SiteX509AttendedUnlockRoleV2.allCases {
            let fixture = try CustodyFixture(role: role)
            let value = try fixture.decode()
            XCTAssertEqual(value.presentation.role, role)
            XCTAssertEqual(value.presentation.deviceKeyID, "site-root-" + fixture.target.hex)
            XCTAssertNotEqual(fixture.registration.ackPublicKeyB64URL, fixture.registration.targetIDB64URL)
            try value.requireExistingRootPublicKey(fixture.rootPublic)
            XCTAssertThrowsError(try value.requireExistingRootPublicKey(Data(repeating: 8, count: 33)))
        }
    }

    func testWrongOrMalformedIndependentDigestIsDenied() throws {
        let fixture = try CustodyFixture()
        for digest in ["", String(repeating: "0", count: 64), fixture.digest + " ",
                       String(repeating: "g", count: 64), "SHA256:" + fixture.digest] {
            XCTAssertThrowsError(try fixture.decode(digest: digest))
        }
        XCTAssertNoThrow(try fixture.decode(digest: fixture.digest.uppercased()))
    }

    func testAuthenticatedChallengeSubstitutionsAreDenied() throws {
        for field in ["fresh_host_public_sec1_b64url", "key_generation", "device_key_id",
                      "site_trust_domain", "delegation_serial", "current_revocation_generation",
                      "expires_at_unix_seconds", "encrypted_record_digest_b64url"] {
            var fixture = try CustodyFixture()
            let trustedDigest = fixture.digest
            switch field {
            case "fresh_host_public_sec1_b64url":
                fixture.object[field] = try P256.KeyAgreement.PrivateKey(
                    rawRepresentation: Data(repeating: 6, count: 32)
                ).publicKey.compressedRepresentation.b64
            case "key_generation": fixture.object[field] = "x509-root-generation-2"
            case "device_key_id": fixture.object[field] = "site-root-" + String(repeating: "a", count: 64)
            case "site_trust_domain": fixture.object[field] = "site-11111111-1111-1111-1111-111111111111"
            case "delegation_serial": fixture.object[field] = "another-registration"
            case "current_revocation_generation": fixture.object[field] = UInt64(8)
            case "expires_at_unix_seconds": fixture.object[field] = UInt64(1_101)
            default:
                let changedRecord = Data(repeating: 9, count: 60)
                fixture.object["existing_encrypted_record_b64url"] = changedRecord.b64
                fixture.object[field] = Data(SHA256.hash(data: changedRecord)).b64
            }
            fixture.rebuildChallenge()
            XCTAssertThrowsError(try fixture.decode(digest: trustedDigest), field)
        }
        XCTAssertThrowsError(try CustodyFixture(role: .issuer).decode(expectedRole: .root))
    }

    func testUnknownImportedDigestDuplicateTrailingAndOversizedJSONAreDenied() throws {
        var fixture = try CustodyFixture()
        fixture.object["independent_digest"] = fixture.digest
        XCTAssertThrowsError(try fixture.decode())
        fixture.object.removeValue(forKey: "independent_digest")
        let data = try fixture.data()
        let text = String(decoding: data, as: UTF8.self)
        let duplicate = Data(("{\"role\":\"root\"," + text.dropFirst()).utf8)
        for bytes in [duplicate, data + Data("{}".utf8),
                      Data(repeating: 32, count: SiteX509OfflineCustodyV2.maximumFileBytes + 1)] {
            XCTAssertThrowsError(try fixture.decode(data: bytes))
        }
    }

    func testMalformedAndWrongProtectedRegistrationsAreDenied() throws {
        let fixture = try CustodyFixture()
        let record = fixture.registration
        let changes = [
            SiteRootConvergenceAckRecordV2(siteUUID: record.siteUUID, targetIDB64URL: record.ackPublicKeyB64URL, ackPublicKeyB64URL: record.ackPublicKeyB64URL, generation: 1),
            SiteRootConvergenceAckRecordV2(siteUUID: record.siteUUID, targetIDB64URL: record.targetIDB64URL + "=", ackPublicKeyB64URL: record.ackPublicKeyB64URL, generation: 1),
            SiteRootConvergenceAckRecordV2(siteUUID: record.siteUUID, targetIDB64URL: record.targetIDB64URL, ackPublicKeyB64URL: record.ackPublicKeyB64URL, generation: 0),
            SiteRootConvergenceAckRecordV2(siteUUID: "11111111-1111-1111-1111-111111111111", targetIDB64URL: record.targetIDB64URL, ackPublicKeyB64URL: record.ackPublicKeyB64URL, generation: 1),
            SiteRootConvergenceAckRecordV2(siteUUID: "00000000-0000-0000-0000-000000000000", targetIDB64URL: record.targetIDB64URL, ackPublicKeyB64URL: record.ackPublicKeyB64URL, generation: 1),
        ]
        for registration in changes { XCTAssertThrowsError(try fixture.decode(registration: registration)) }
        XCTAssertThrowsError(try fixture.decode(now: 1_100))
    }

    @MainActor
    func testMissingRecordAndKeyStopBeforeInjectedAuthentication() async throws {
        for missingRecord in [true, false] {
            var authenticated = false
            var produced = false
            do {
                _ = try await SiteX509OfflineCustodyV2.perform(
                    requireCurrent: { if missingRecord { throw PlatformFailure.siteRootAuthorityUnavailable } },
                    requireExistingKey: { throw PlatformFailure.keyNotFound },
                    authenticate: { authenticated = true; return () },
                    produce: { _ in produced = true; return Data() }
                )
                XCTFail("Missing authority must deny")
            } catch {}
            XCTAssertFalse(authenticated)
            XCTAssertFalse(produced)
        }
    }

    @MainActor
    func testExpiryAndRegistrationReplacementAfterAuthenticationPreventProduction() async throws {
        let fixture = try CustodyFixture()
        let value = try fixture.decode()
        for replaceRecord in [true, false] {
            var now: UInt64 = 1_000
            var record = fixture.registration
            var produced = false
            do {
                _ = try await SiteX509OfflineCustodyV2.perform(
                    requireCurrent: { try value.requireCurrent(registration: record, nowUnixSeconds: now) },
                    requireExistingKey: {},
                    authenticate: {
                        if replaceRecord {
                            record = SiteRootConvergenceAckRecordV2(
                                siteUUID: record.siteUUID, targetIDB64URL: record.targetIDB64URL,
                                ackPublicKeyB64URL: record.ackPublicKeyB64URL, generation: record.generation + 1
                            )
                        } else { now = 1_100 }
                        return ()
                    },
                    produce: { _ in produced = true; return Data() }
                )
                XCTFail("Changed authority or expiry must deny")
            } catch {}
            XCTAssertFalse(produced)
        }
    }

    @MainActor
    func testCancellationAndReplacedOperationPreventResponse() async throws {
        for cancel in [true, false] {
            var current = true
            var produced = false
            do {
                _ = try await SiteX509OfflineCustodyV2.perform(
                    requireCurrent: { if !current { throw PlatformFailure.operationCancelled } },
                    requireExistingKey: {},
                    authenticate: {
                        if cancel { throw PlatformFailure.userVerificationCancelled }
                        current = false
                        return ()
                    },
                    produce: { _ in produced = true; return Data() }
                )
                XCTFail("Cancellation must deny")
            } catch {}
            XCTAssertFalse(produced)
        }
    }

    @MainActor
    func testResponseIsWithheldIfCurrentOperationChangesDuringProduction() async throws {
        var current = true
        do {
            _ = try await SiteX509OfflineCustodyV2.perform(
                requireCurrent: { if !current { throw PlatformFailure.operationCancelled } },
                requireExistingKey: {}, authenticate: { () },
                produce: { _ in current = false; return Data([1]) }
            )
            XCTFail("A changed operation must not export")
        } catch {}
    }

    @MainActor
    func testSuccessfulInjectedSequenceChecksAuthorityAroundEachStage() async throws {
        var order: [String] = []
        let response = try await SiteX509OfflineCustodyV2.perform(
            requireCurrent: { order.append("current") },
            requireExistingKey: { order.append("key") },
            authenticate: { order.append("authenticate"); return () },
            produce: { _ in order.append("produce"); return Data([7]) }
        )
        XCTAssertEqual(response, Data([7]))
        XCTAssertEqual(order, ["current", "key", "authenticate", "current", "key", "produce", "current"])
    }

    @MainActor
    func testImportReplacementAndCancellationClearCoordinatorState() {
        let coordinator = SiteX509OfflineCustodyCoordinatorV2()
        coordinator.accept(Data([1]))
        let first = coordinator.importedID
        coordinator.accept(Data([2]))
        XCTAssertNotNil(first)
        XCTAssertNotEqual(first, coordinator.importedID)
        coordinator.cancel()
        XCTAssertNil(coordinator.importedID)
        XCTAssertNil(coordinator.validated)
        XCTAssertNil(coordinator.responseBytes)
    }
}

/// Fixed test-only P-256 material and synthetic ciphertext; never installed custody.
private struct CustodyFixture {
    var object: [String: Any]
    let registration: SiteRootConvergenceAckRecordV2
    let rootPublic: Data
    let target: Data
    let role: SiteX509AttendedUnlockRoleV2

    init(role: SiteX509AttendedUnlockRoleV2 = .root) throws {
        self.role = role
        rootPublic = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 5, count: 32))
            .publicKey.compressedRepresentation
        target = Data(SHA256.hash(data: rootPublic))
        registration = SiteRootConvergenceAckRecordV2(
            siteUUID: "6073349b-e7f6-420f-ba7c-586b6d9ad78e", targetIDB64URL: target.b64,
            ackPublicKeyB64URL: Data(repeating: 9, count: 33).b64, generation: 1
        )
        let record = Data(repeating: 0x44, count: 60)
        object = [
            "schema": SiteX509AttendedUnlockRoleV2.presentationSchema,
            "role": role.rawValue, "purpose": role.purpose,
            "correlation_b64url": Data(repeating: 1, count: 16).b64,
            "fresh_host_public_sec1_b64url": try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32)).publicKey.compressedRepresentation.b64,
            "site_trust_domain": "site-" + registration.siteUUID,
            "key_generation": role.generationPrefix + "generation-1",
            "device_key_id": "site-root-" + target.hex,
            "expected_p256_public_sec1_b64url": try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 4, count: 32)).publicKey.compressedRepresentation.b64,
            "encrypted_record_digest_b64url": Data(SHA256.hash(data: record)).b64,
            "current_revocation_generation": UInt64(7),
            "delegation_serial": "protected-registration-fixture",
            "expires_at_unix_seconds": UInt64(1_100),
            "existing_host_public_sec1_b64url": try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 2, count: 32)).publicKey.compressedRepresentation.b64,
            "existing_encrypted_record_b64url": record.b64,
            "submission_path": role.submissionPath,
        ]
        rebuildChallenge()
    }

    var digest: String {
        Data(SHA256.hash(data: Data(base64Encoded: (object["canonical_challenge_b64url"] as! String)
            .replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            .padding(toLength: ((object["canonical_challenge_b64url"] as! String).count + 3) / 4 * 4,
                     withPad: "=", startingAt: 0))!)).hex
    }

    mutating func rebuildChallenge() {
        func binary(_ name: String) -> Data {
            let text = object[name] as! String
            return Data(base64Encoded: text.replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
                .padding(toLength: (text.count + 3) / 4 * 4, withPad: "=", startingAt: 0))!
        }
        var challenge = Data("thesaurophylax.site-x509-iphone-rewrap.v2\0".utf8)
        let fields: [Data] = [
            Data([role.challengeCode]), Data((object["site_trust_domain"] as! String).utf8),
            Data((object["key_generation"] as! String).utf8), Data((object["device_key_id"] as! String).utf8),
            binary("expected_p256_public_sec1_b64url"), binary("encrypted_record_digest_b64url"),
            Data((object["current_revocation_generation"] as! UInt64).bytes),
            Data((object["delegation_serial"] as! String).utf8),
            Data((object["expires_at_unix_seconds"] as! UInt64).bytes), binary("fresh_host_public_sec1_b64url"),
        ]
        for (index, field) in fields.enumerated() {
            challenge.append(UInt8(index + 1))
            challenge.append(contentsOf: UInt16(field.count).bytes)
            challenge.append(field)
        }
        object["canonical_challenge_b64url"] = challenge.b64
    }

    func data() throws -> Data { try JSONSerialization.data(withJSONObject: object) }
    func decode(
        data: Data? = nil, digest: String? = nil,
        registration: SiteRootConvergenceAckRecordV2? = nil, now: UInt64 = 1_000,
        expectedRole: SiteX509AttendedUnlockRoleV2? = nil
    ) throws -> SiteX509OfflineCustodyV2 {
        try SiteX509OfflineCustodyV2(
            data: data ?? self.data(), expectedRole: expectedRole ?? role,
            independentDigestHex: digest ?? self.digest,
            registration: registration ?? self.registration, nowUnixSeconds: now
        )
    }
}

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
    var b64: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
private extension FixedWidthInteger {
    var bytes: [UInt8] { withUnsafeBytes(of: bigEndian, Array.init) }
}
