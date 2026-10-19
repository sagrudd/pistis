import Foundation
import XCTest
@testable import PistisCore
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

final class NativeInstallApprovalTests: XCTestCase {
    // Synthetic closed-graph DATA only. No native owner, attended act or key
    // trust is established by these deterministic public fixture values.
    private struct Graph {
        var record: [IssuerCBOR]
        var scope: [IssuerCBOR]
        func task() throws -> Data {
            var r = record
            var policy = try r[23].array(6)
            let scopeBytes = try IssuerCBOR.array(scope).encoded()
            policy[2] = .bytes(scopeBytes); r[23] = .array(policy)
            let capture = try IssuerCBOR.array(r).encoded()
            let body = try IssuerCBOR.array([.unsigned(1),NativeInstallApprovalTests.b("issuer-native-install-purpose-approval-v1"),.bytes(NativeInstallApprovalTests.d(5,16)),.bytes(NativeInstallApprovalTests.d(6)),.unsigned(100),.unsigned(120),policy[0],.bytes(IssuerPhoneWire.sha256(capture)),.bytes(capture),.bytes(scopeBytes)]).encoded()
            return try IssuerCBOR.array([.unsigned(1),.unsigned(8),.bytes(NativeInstallApprovalTests.d(4,16)),.bytes(body),.bytes(try policy[5].bytes()),.bytes(IssuerPhoneWire.sha256(body))]).encoded()
        }
    }
    private static func d(_ byte: UInt8, _ count: Int = 32) -> Data { Data(repeating: byte, count: count) }
    private static func b(_ string: String) -> IssuerCBOR { .bytes(Data(string.utf8)) }
    private static func hex(_ data: Data) -> String { data.map { String(format:"%02x",$0) }.joined() }
    private func graph() throws -> Graph {
        let install=Self.d(1,16),site=Self.d(2,16)
        let root=try P256.Signing.PrivateKey(rawRepresentation:Self.d(3)).publicKey.compressedRepresentation
        let ack=try P256.Signing.PrivateKey(rawRepresentation:Self.d(4)).publicKey.compressedRepresentation
        let keys=try [UInt8(5),6,7].map { try P256.Signing.PrivateKey(rawRepresentation:Self.d($0)).publicKey.compressedRepresentation }
        let purpose="thesaurophylax.github-exact-source-qualification-credential-projection.v1"
        let life=IssuerPhoneWire.sha256(try IssuerCBOR.array([.unsigned(1),Self.b("issuer-native-purpose-lifecycle-v1"),.bytes(install),.bytes(site),Self.b(purpose)]).encoded())
        let boot="03030303-0303-0303-0303-030303030303",config=Self.d(13),native=Self.d(14)
        let roles=[("jenkins",purpose),("proxenos","mnemosyne.proxenos.jenkins-exact-source-observation.v1"),("thesaurophylax","mnemosyne.thesaurophylax.jenkins-exact-source-issuer-observation.v1")]
        let services:[[String:Any]]=roles.enumerated().map { i,role in
            ["component":role.0,"profile":role.1,"uid":100+i,"gid":200+i,"executable_device":"1","executable_inode":"2","executable_sha256":Self.hex(Self.d(30)),"mount_namespace_inode":"3","package_manifest_sha256":Self.hex(Self.d(31)),"package_artifact_sha256":Self.hex(Self.d(32)),"payload_inventory_sha256":Self.hex(Self.d(33))]
        }
        let measured:[String:Any]=["schema":"mnemosyne.proxenos.exact-source-installed-measurement.v1","installation_id":"01010101-0101-0101-0101-010101010101","site_uuid":"02020202-0202-0202-0202-020202020202","site":"Home","boot_id":boot,"configuration_sha256":Self.hex(config),"lockset_id":"test-lockset","lockset_sha256":Self.hex(Self.d(15)),"registry_sha256":Self.hex(Self.d(16)),"release_authority_sha256":Self.hex(Self.d(17)),"native_admissions_sha256":Self.hex(native),"services":services]
        let measurement=try JSONSerialization.data(withJSONObject:measured,options:[.sortedKeys,.withoutEscapingSlashes])
        let placement=try IssuerCBOR.array([.unsigned(1),Self.b("issuer-native-purpose-key-custody-placement-v1"),Self.b("thesaurophylax"),Self.b(roles[2].1),.bytes(Self.d(31)),.bytes(Self.d(30)),.array([.unsigned(102),.unsigned(202)]),Self.b(boot),.array([.unsigned(1),.unsigned(2)]),.array([.unsigned(4),.unsigned(3)]),.array([Self.b("W"),Self.b("P"),Self.b("T")]),Self.b("process-local-prepared-private-keys-no-restoration-v1")]).encoded()
        let recovery=try IssuerCBOR.array([.unsigned(1),Self.b("no-native-purpose-recovery-authorized-v1")]).encoded()
        let purposes=[["IHIS/1","IRSP/1","IROT/1"],["INAT/1","ICMT/1"],["ICMT/1"]]
        let requested=zip(["W","P","T"],keys).enumerated().map { i,pair in IssuerCBOR.array([Self.b(pair.0),Self.b("ES256"),.unsigned(1),.bytes(pair.1),.array(purposes[i].map(Self.b))]) }
        let scope:[IssuerCBOR]=[.unsigned(1),Self.b("issuer-pre-root-native-scope-v1"),Self.b("classic-commit-status:mnemosyne/expedition"),Self.b("Home"),.array(requested),.array([.unsigned(1),Self.b("fresh-native-purpose-only-v1"),Self.b("independent-existing-issuance-checkpoint-at-commit-v1")]),.bytes(recovery),.bytes(life),.bytes(IssuerPhoneWire.sha256(placement))]
        let ackTarget=IssuerPhoneWire.sha256(root),target=Self.d(18)
        let selection=try IssuerCBOR.array([.bytes(site),.bytes(ackTarget),.unsigned(1),.bytes(ack),.bytes(target),.unsigned(3),.unsigned(1),.bytes(Self.d(19))]).encoded()
        let spec=Data([0x9a,0x84,0x27,0x96,0x11,0xdc,0x44,0x2e,0x77,0xf3,0xad,0x2b,0x3a,0xd9,0x48,0x77,0x7c,0xf6,0x00,0x39,0xc8,0x37,0x56,0x3b,0xb7,0x9e,0x57,0xff,0xd0,0x01,0x88,0xcd])
        let record:[IssuerCBOR]=[.unsigned(1),Self.b("issuer-native-purpose-current-record-v1"),.bytes(life),.bytes(Self.d(8,16)),.bytes(install),.bytes(site),.bytes(target),.bytes(Self.d(9,16)),.bytes(Self.d(10,16)),.bytes(Self.d(11,16)),Self.b(String(repeating:"a",count:64)),.unsigned(1),.unsigned(1),.unsigned(1),.unsigned(1),.unsigned(1),.unsigned(130),.bytes(measurement),.bytes(native),.array([.bytes(site),.bytes(ackTarget),.unsigned(1),.bytes(ack),.bytes(root)]),.array(keys.map { .bytes($0) }),.array([.bytes(Self.d(20)),Self.b("old-credential-generation"),.unsigned(0),Self.b(purpose)]),.array([Self.b("owner/repository"),.bytes(Self.d(21,20)),.bytes(config),.unsigned(150),.bytes(Self.d(22)),.bytes(Self.d(23)),.bytes(Self.d(24))]),.array([.bytes(spec),.bytes(Self.d(25)),.bytes(Data()),.bytes(placement),.bytes(Self.d(26)),.bytes(selection)])]
        return Graph(record:record,scope:scope)
    }
    func testExactGraphRetainsRequestedKeysAndExplicitNoRecovery() throws {
        let value=try NativeInstallApprovalTask(canonicalBytes:graph().task(),now:101)
        XCTAssertEqual(value.siteLabel,"Home");XCTAssertEqual(value.requestedKeys.map(\.role),["W","P","T"])
        XCTAssertEqual(value.requestedKeys[1].purposes,["INAT/1","ICMT/1"])
        XCTAssertNotEqual(value.nativeTarget,value.acknowledgementTarget)
    }
    func testReboundLifecycleAndIssuerPurposeCannotAppointNewLifecycle() throws {
        var g=try graph();g.record[2] = .bytes(Self.d(70));g.scope[7]=g.record[2]
        XCTAssertThrowsError(try NativeInstallApprovalTask(canonicalBytes:g.task(),now:101))
        g=try graph();var old=try g.record[21].array(4);old[3]=Self.b("another-purpose");g.record[21] = .array(old)
        XCTAssertThrowsError(try NativeInstallApprovalTask(canonicalBytes:g.task(),now:101))
    }
    func testReboundACKTupleStillRequiresActualSiteRootHash() throws {
        var g=try graph();var ack=try g.record[19].array(5);ack[1] = .bytes(Self.d(71));g.record[19] = .array(ack)
        var policy=try g.record[23].array(6);var s=try IssuerCBOR.decode(policy[5].bytes()).array(8);s[1]=ack[1]
        policy[5] = .bytes(try IssuerCBOR.array(s).encoded());g.record[23] = .array(policy)
        XCTAssertThrowsError(try NativeInstallApprovalTask(canonicalBytes:g.task(),now:101))
    }
    func testReboundMeasurementAndUnknownRecoveryRemainDenied() throws {
        var g=try graph();g.record[17] = .bytes(Data("[]".utf8))
        XCTAssertThrowsError(try NativeInstallApprovalTask(canonicalBytes:g.task(),now:101))
        g=try graph();g.scope[6] = .bytes(try IssuerCBOR.array([.unsigned(1),Self.b("allow-reset")]).encoded())
        XCTAssertThrowsError(try NativeInstallApprovalTask(canonicalBytes:g.task(),now:101))
    }
    func testExpiryKindAndCanonicalBoundsDeny() throws {
        let raw=try graph().task()
        XCTAssertThrowsError(try NativeInstallApprovalTask(canonicalBytes:raw,now:120))
        var task=try IssuerCBOR.decode(raw).array(6);task[1] = .unsigned(7)
        XCTAssertThrowsError(try NativeInstallApprovalTask(canonicalBytes:IssuerCBOR.array(task).encoded(),now:101))
        XCTAssertThrowsError(try NativeInstallApprovalTask(canonicalBytes:raw+Data([0]),now:101))
        task=try IssuerCBOR.decode(raw).array(6);task[4] = .bytes(Data([1]))
        // Former registration-shaped/opaque values have no fallback meaning.
        XCTAssertThrowsError(try NativeInstallApprovalTask(canonicalBytes:IssuerCBOR.array(task).encoded(),now:101))
    }

    func testMeasurementRejectsBooleanFractionAndOutOfRangeIdentities() throws {
        for invalid: Any in [true, 102.5, UInt64(UInt32.max) + 1, 0, -1] {
            var g = try graph()
            var measurement = try XCTUnwrap(JSONSerialization.jsonObject(with: g.record[17].bytes()) as? [String: Any])
            var services = try XCTUnwrap(measurement["services"] as? [[String: Any]])
            services[2]["uid"] = invalid
            measurement["services"] = services
            g.record[17] = .bytes(try JSONSerialization.data(withJSONObject: measurement, options: [.sortedKeys, .withoutEscapingSlashes]))
            XCTAssertThrowsError(try NativeInstallApprovalTask(canonicalBytes: g.task(), now: 101))
        }
    }
    func testMeasurementRejectsUnknownFieldsAndNoncanonicalIdentityStrings() throws {
        for field in ["unexpected", "executable_device", "mount_namespace_inode"] {
            var g = try graph()
            var measurement = try XCTUnwrap(JSONSerialization.jsonObject(with: g.record[17].bytes()) as? [String: Any])
            var services = try XCTUnwrap(measurement["services"] as? [[String: Any]])
            services[2][field] = "01"
            measurement["services"] = services
            g.record[17] = .bytes(try JSONSerialization.data(withJSONObject: measurement, options: [.sortedKeys, .withoutEscapingSlashes]))
            XCTAssertThrowsError(try NativeInstallApprovalTask(canonicalBytes: g.task(), now: 101))
        }
    }
    func testReboundPlacementCannotReplaceMeasuredImageOwnerOrNamespace() throws {
        for index in [4, 5, 6, 7, 8, 9, 10, 11] {
            var g = try graph()
            var policy = try g.record[23].array(6)
            var placement = try IssuerCBOR.decode(policy[3].bytes()).array(12)
            switch index {
            case 4, 5: placement[index] = .bytes(Self.d(77))
            case 6: placement[index] = .array([.unsigned(103), .unsigned(202)])
            case 7: placement[index] = Self.b("04040404-0404-0404-0404-040404040404")
            case 8: placement[index] = .array([.unsigned(1), .unsigned(99)])
            case 9: placement[index] = .array([.unsigned(4), .unsigned(99)])
            case 10: placement[index] = .array([Self.b("T"), Self.b("P"), Self.b("W")])
            default: placement[index] = Self.b("restorable-private-keys")
            }
            let raw = try IssuerCBOR.array(placement).encoded()
            policy[3] = .bytes(raw)
            g.record[23] = .array(policy)
            // Rebind the public digest too: semantic comparisons, rather than
            // a stale digest, must reject the substituted custody placement.
            g.scope[8] = .bytes(IssuerPhoneWire.sha256(raw))
            XCTAssertThrowsError(try NativeInstallApprovalTask(canonicalBytes: g.task(), now: 101))
        }
    }
    func testPhoneNonceIsSeparateCorrelationInPrepareAndSubmission() throws {
        let phoneNonce = Self.d(80)
        let prepare = try NativeInstallApprovalWire.prepare(operationID: Self.d(5, 16),
            requestDigest: Self.d(81), expectationDigest: Self.d(82), queryDigest: Self.d(83),
            sourceFingerprint: Self.d(84), phoneNonce: phoneNonce)
        let fields = try IssuerCBOR.decode(prepare).array(8)
        XCTAssertEqual(fields[7], .bytes(phoneNonce))
        let task = try NativeInstallApprovalTask(canonicalBytes: graph().task(), now: 101)
        XCTAssertNotEqual(task.nonce, phoneNonce)
        // Synthetic proof-shaped DATA only; encoding does not authenticate it.
        let proof = Self.d(85, 83)
        let response = try IssuerCBOR.decode(NativeInstallApprovalWire.submission(task: task,
            phoneNonce: phoneNonce, detachedACKProof: proof)).array(6)
        XCTAssertEqual(response[2], .bytes(task.taskID))
        XCTAssertEqual(response[3], .bytes(task.bodyDigest))
        XCTAssertEqual(response[4], .bytes(phoneNonce))
        XCTAssertEqual(response[5], .bytes(proof))
        XCTAssertThrowsError(try NativeInstallApprovalWire.submission(task: task,
            phoneNonce: Data(repeating: 0, count: 32), detachedACKProof: proof))
        XCTAssertThrowsError(try NativeInstallApprovalWire.submission(task: task,
            phoneNonce: phoneNonce, detachedACKProof: Data(proof.dropLast())))
    }

    func testPlanAndReceiptUseClosedShapesAndExactRetainedCorrelation() throws {
        let phoneNonce = Self.d(80)
        let request = try NativeInstallApprovalWire.prepare(operationID: Self.d(5, 16), requestDigest: Self.d(81),
            expectationDigest: Self.d(82), queryDigest: Self.d(83), sourceFingerprint: Self.d(84), phoneNonce: phoneNonce)
        var planFields = try IssuerCBOR.decode(request).array(8)
        planFields.removeLast()
        let planRaw = try IssuerCBOR.array(planFields).encoded()
        let plan = try NativeInstallApprovalWire.Plan(canonicalBytes: planRaw)
        XCTAssertEqual(try NativeInstallApprovalWire.prepare(plan: plan, phoneNonce: phoneNonce), request)
        XCTAssertThrowsError(try NativeInstallApprovalWire.Plan(canonicalBytes: request))
        XCTAssertThrowsError(try NativeInstallApprovalWire.Plan(canonicalBytes: planRaw + Data([0])))
        let task = try NativeInstallApprovalTask(canonicalBytes: graph().task(), now: 101)
        var receipt: [IssuerCBOR] = [.unsigned(1), .unsigned(8), .bytes(task.taskID), .bytes(task.bodyDigest),
            .bytes(phoneNonce), Self.b("accepted-native-purpose-v1")]
        try NativeInstallApprovalWire.accepted(IssuerCBOR.array(receipt).encoded(), task: task, phoneNonce: phoneNonce)
        receipt[4] = .bytes(task.nonce)
        XCTAssertThrowsError(try NativeInstallApprovalWire.accepted(IssuerCBOR.array(receipt).encoded(), task: task, phoneNonce: phoneNonce))
        receipt[4] = .bytes(phoneNonce); receipt[3] = .bytes(Self.d(90))
        XCTAssertThrowsError(try NativeInstallApprovalWire.accepted(IssuerCBOR.array(receipt).encoded(), task: task, phoneNonce: phoneNonce))
        receipt[3] = .bytes(task.bodyDigest); receipt[5] = Self.b("prepared-native-purpose-v1")
        XCTAssertThrowsError(try NativeInstallApprovalWire.accepted(IssuerCBOR.array(receipt).encoded(), task: task, phoneNonce: phoneNonce))
    }

}
