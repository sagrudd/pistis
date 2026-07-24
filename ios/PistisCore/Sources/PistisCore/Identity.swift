import Foundation

public enum ExternalIdentityProvider: String, Codable, CaseIterable, Sendable {
    case github
    case google
}

public enum IdentityBindingState: String, Codable, Sendable {
    case pending
    case bound
    case needsReenrolment = "needs_reenrolment"
    case removed
}

public struct ExternalIdentity: Codable, Equatable, Sendable {
    public let id: IdentityID
    public let provider: ExternalIdentityProvider
    public let providerSubject: String
    public let displayName: String
    public let bindingState: IdentityBindingState
    public let boundDeviceID: DeviceID
    public let observedAt: Date

    public init(
        id: IdentityID,
        provider: ExternalIdentityProvider,
        providerSubject: String,
        displayName: String,
        bindingState: IdentityBindingState,
        boundDeviceID: DeviceID,
        observedAt: Date
    ) throws {
        guard !providerSubject.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              providerSubject.utf8.count <= 256
        else {
            throw DomainValidationError.invalidIdentifier
        }
        guard !displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              displayName.utf8.count <= 256
        else {
            throw DomainValidationError.missingDisplayName
        }
        self.id = id
        self.provider = provider
        self.providerSubject = providerSubject
        self.displayName = displayName
        self.bindingState = bindingState
        self.boundDeviceID = boundDeviceID
        self.observedAt = observedAt
    }
}

public struct IdentityStore: Equatable, Sendable {
    public private(set) var identities: [IdentityID: ExternalIdentity]

    public init(identities: [IdentityID: ExternalIdentity] = [:]) {
        self.identities = identities
    }

    public mutating func record(_ identity: ExternalIdentity) throws {
        if let existing = identities[identity.id],
           (existing.provider != identity.provider ||
            existing.providerSubject != identity.providerSubject) {
            throw IdentityStoreError.stableIdentityConflict
        }
        identities[identity.id] = identity
    }

    public func identity(_ id: IdentityID) -> ExternalIdentity? {
        identities[id]
    }
}

public enum IdentityStoreError: Error, Equatable, Sendable {
    case stableIdentityConflict
}
