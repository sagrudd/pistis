import Foundation
import CoreFoundation

/// Semantic comparison of the exact producer's supported measurement and
/// placement. This recognises DATA only and cannot establish installed trust.
enum NativeInstallMeasurement {
    static func validate(_ raw: Data, placement: Data, installation: Data, site: Data,
                         label: String, configuration: Data, nativeDigest: Data) throws {
        guard let m = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
              Set(m.keys) == Set(["schema","installation_id","site_uuid","site","boot_id","configuration_sha256","lockset_id","lockset_sha256","registry_sha256","release_authority_sha256","native_admissions_sha256","services"]),
              try JSONSerialization.data(withJSONObject: m, options: [.sortedKeys,.withoutEscapingSlashes]) == raw,
              m["schema"] as? String == "mnemosyne.proxenos.exact-source-installed-measurement.v1",
              m["installation_id"] as? String == uuidText(installation), m["site_uuid"] as? String == uuidText(site),
              m["site"] as? String == label, m["configuration_sha256"] as? String == hex(configuration),
              m["native_admissions_sha256"] as? String == hex(nativeDigest),
              let boot = m["boot_id"] as? String, let bootID = UUID(uuidString: boot),
              bootID.uuidString.lowercased() == boot, boot != "00000000-0000-0000-0000-000000000000",
              let services = m["services"] as? [[String: Any]], services.count == 3 else { throw IssuerPhoneError.binding }
        _ = try text(m["lockset_id"], maximum: 255)
        for name in ["lockset_sha256","registry_sha256","release_authority_sha256","native_admissions_sha256"] { _ = try digest(m[name]) }
        let expected = [("jenkins","thesaurophylax.github-exact-source-qualification-credential-projection.v1"),
                        ("proxenos","mnemosyne.proxenos.jenkins-exact-source-observation.v1"),
                        ("thesaurophylax","mnemosyne.thesaurophylax.jenkins-exact-source-issuer-observation.v1")]
        for (index, role) in expected.enumerated() {
            let s = services[index]
            guard Set(s.keys) == Set(["component","profile","uid","gid","executable_device","executable_inode","executable_sha256","mount_namespace_inode","package_manifest_sha256","package_artifact_sha256","payload_inventory_sha256"]),
                  s["component"] as? String == role.0, s["profile"] as? String == role.1 else { throw IssuerPhoneError.binding }
            _ = try integer(s["uid"]); _ = try integer(s["gid"])
            for name in ["executable_device","executable_inode","mount_namespace_inode"] { _ = try decimal(s[name]) }
            for name in ["executable_sha256","package_manifest_sha256","package_artifact_sha256","payload_inventory_sha256"] { _ = try digest(s[name]) }
        }
        try validatePlacement(placement, thes: services[2], boot: boot)
    }
    private static func validatePlacement(_ raw: Data, thes: [String: Any], boot: String) throws {
        let p = try IssuerCBOR.decode(raw, maximum: 8192).array(12)
        guard p[0] == .unsigned(1), try p[1].bytes() == Data("issuer-native-purpose-key-custody-placement-v1".utf8),
              try p[2].bytes() == Data("thesaurophylax".utf8),
              try p[3].bytes() == Data("mnemosyne.thesaurophylax.jenkins-exact-source-issuer-observation.v1".utf8),
              try hex(p[4].bytes(32, nonzero: true)) == digest(thes["package_manifest_sha256"]),
              try hex(p[5].bytes(32, nonzero: true)) == digest(thes["executable_sha256"]),
              try p[7].bytes() == Data(boot.utf8),
              try p[10].array(3) == ["W","P","T"].map({ .bytes(Data($0.utf8)) }),
              try p[11].bytes() == Data("process-local-prepared-private-keys-no-restoration-v1".utf8) else { throw IssuerPhoneError.binding }
        let owner = try p[6].array(2), image = try p[8].array(2), namespace = try p[9].array(2)
        guard try owner[0].uint(1...UInt64(UInt32.max)) == integer(thes["uid"]),
              try owner[1].uint(1...UInt64(UInt32.max)) == integer(thes["gid"]),
              try image[0].uint(1...UInt64.max) == decimal(thes["executable_device"]),
              try image[1].uint(1...UInt64.max) == decimal(thes["executable_inode"]),
              try namespace[1].uint(1...UInt64.max) == decimal(thes["mount_namespace_inode"]) else { throw IssuerPhoneError.binding }
        _ = try namespace[0].uint(1...UInt64.max)
    }
    private static func text(_ value: Any?, maximum: Int) throws -> String {
        guard let s = value as? String, !s.isEmpty, s.utf8.count <= maximum,
              s.utf8.allSatisfy({ 32...126 ~= $0 }) else { throw IssuerPhoneError.binding }
        return s
    }
    private static func digest(_ value: Any?) throws -> String {
        let s = try text(value, maximum: 64)
        guard s.utf8.count == 64, s.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              s != String(repeating: "0", count: 64) else { throw IssuerPhoneError.binding }
        return s
    }
    private static func decimal(_ value: Any?) throws -> UInt64 {
        let s = try text(value, maximum: 20)
        guard let n = UInt64(s), n > 0, String(n) == s else { throw IssuerPhoneError.binding }
        return n
    }
    private static func integer(_ value: Any?) throws -> UInt64 {
        guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(),
              n.doubleValue > 0, n.doubleValue <= Double(UInt32.max),
              n.doubleValue == Double(n.uint64Value) else { throw IssuerPhoneError.binding }
        return n.uint64Value
    }
    private static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    private static func uuidText(_ raw: Data) -> String {
        let h = Array(hex(raw)); return [String(h[0..<8]),String(h[8..<12]),String(h[12..<16]),String(h[16..<20]),String(h[20..<32])].joined(separator: "-")
    }
}
