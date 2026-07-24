import Foundation

public struct DomainIdentifier<Tag>: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init?(rawValue: String) {
        guard Self.isValid(rawValue) else { return nil }
        self.rawValue = rawValue
    }

    public init(validating value: String) throws {
        guard let identifier = Self(rawValue: value) else {
            throw DomainValidationError.invalidIdentifier
        }
        self = identifier
    }

    private static func isValid(_ value: String) -> Bool {
        guard (1...128).contains(value.utf8.count),
              value == value.trimmingCharacters(in: .whitespacesAndNewlines)
        else {
            return false
        }
        return value.unicodeScalars.allSatisfy {
            CharacterSet.alphanumerics.contains($0) || "-_.:".unicodeScalars.contains($0)
        }
    }
}

public enum IdentityIDTag: Sendable {}
public enum InstallationIDTag: Sendable {}
public enum DeviceIDTag: Sendable {}
public enum ChallengeIDTag: Sendable {}
public enum EvidenceIDTag: Sendable {}

public typealias IdentityID = DomainIdentifier<IdentityIDTag>
public typealias InstallationID = DomainIdentifier<InstallationIDTag>
public typealias DeviceID = DomainIdentifier<DeviceIDTag>
public typealias ChallengeID = DomainIdentifier<ChallengeIDTag>
public typealias EvidenceID = DomainIdentifier<EvidenceIDTag>

public enum DomainValidationError: Error, Equatable, Sendable {
    case invalidIdentifier
    case missingDisplayName
    case invalidFingerprint
    case invalidTimeRange
    case invalidURL
}

public struct SHA256Fingerprint: RawRepresentable, Codable, Hashable, Sendable {
    public let rawValue: String

    public init?(rawValue: String) {
        let normalized = rawValue.lowercased()
        guard normalized.count == 64,
              normalized.utf8.allSatisfy({
                  ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
              })
        else {
            return nil
        }
        self.rawValue = normalized
    }

    public init(validating value: String) throws {
        guard let fingerprint = Self(rawValue: value) else {
            throw DomainValidationError.invalidFingerprint
        }
        self = fingerprint
    }

    public var abbreviated: String {
        "\(rawValue.prefix(8))…\(rawValue.suffix(8))"
    }
}
