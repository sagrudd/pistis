import Foundation

// Retained state is not a trusted authority context. Its adapter must already be
// independently established and protected; no missing-store initialisation path.
struct ContinuityOperationIdentity: Equatable, Hashable, Sendable {
    let operation: Data
    let kind: ContinuityApprovalKind
}
enum ContinuityOperationPhase: String, Codable, Sendable {
    case preparedNoKeyInvocation, dispatchFenced, signedRetained, terminalProvenUnsigned, unresolved
}
struct ContinuityRetainedOperation: Sendable {
    let identity: ContinuityOperationIdentity
    let body: Data
    let phase: ContinuityOperationPhase
    let envelope: Data?
}
protocol ContinuityApprovalLedger: Sendable {
    func read(_ identity: ContinuityOperationIdentity) async throws -> ContinuityRetainedOperation?
    /// Atomic unique identity/body reservation; existing exact record returned read-only.
    func reserve(_ identity: ContinuityOperationIdentity, exactBody: Data) async throws -> ContinuityRetainedOperation
    /// Durable compare-and-set prepared→fenced before private invocation.
    func fence(_ identity: ContinuityOperationIdentity, exactBody: Data) async throws
    func neverInvoked(_ identity: ContinuityOperationIdentity, exactBody: Data) async throws
    /// Exact verified result must be durable before any caller receives it.
    func retain(_ identity: ContinuityOperationIdentity, exactBody: Data, envelope: Data) async throws
    func unresolved(_ identity: ContinuityOperationIdentity, exactBody: Data) async throws
}
struct UnavailableContinuityLedger: ContinuityApprovalLedger {
    func read(_ identity: ContinuityOperationIdentity) async throws -> ContinuityRetainedOperation? { throw ContinuityApprovalError.unavailableLedger }
    func reserve(_ identity: ContinuityOperationIdentity, exactBody: Data) async throws -> ContinuityRetainedOperation { throw ContinuityApprovalError.unavailableLedger }
    func fence(_ identity: ContinuityOperationIdentity, exactBody: Data) async throws { throw ContinuityApprovalError.unavailableLedger }
    func neverInvoked(_ identity: ContinuityOperationIdentity, exactBody: Data) async throws { throw ContinuityApprovalError.unavailableLedger }
    func retain(_ identity: ContinuityOperationIdentity, exactBody: Data, envelope: Data) async throws { throw ContinuityApprovalError.unavailableLedger }
    func unresolved(_ identity: ContinuityOperationIdentity, exactBody: Data) async throws { throw ContinuityApprovalError.unavailableLedger }
}
