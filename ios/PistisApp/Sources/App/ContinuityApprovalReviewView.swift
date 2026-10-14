import Foundation
import PistisCore
import SwiftUI

/// Exact tuple review only. Genuine current-purpose enrolment/bridge remains
/// unavailable, so this view never requests biometric authentication or signing.
struct ContinuityApprovalReviewView: View {
    let presentation: ValidatedContinuityPresentation

    var body: some View {
        Form {
            Section("Approval status") {
                Text("Approval unavailable: current credential enrolment and revocation have not been independently verified.")
                Text("Descriptor → mode selection → issuer attestation")
            }
            Section("Site and service") {
                fact("Site", presentation.allocation.scope.site)
                fact("Root fingerprint", presentation.allocation.scope.rootSPKI)
                fact("Host", presentation.allocation.scope.host)
                Text("Host epoch: \(presentation.allocation.scope.hostEpoch)")
                Text("Authority epoch: \(presentation.descriptor.authorityEpoch)")
                fact("Service", presentation.allocation.scope.service)
                Text(presentation.allocation.scope.maintenanceOrigin)
                Text(presentation.allocation.scope.publicOrigin)
                ForEach(presentation.allocation.scope.privateIPs, id: \.self) { Text($0) }
            }
            Section("Purpose keys and generation records") {
                ForEach(Array(presentation.descriptor.roles.enumerated()), id: \.offset) { index, role in
                    VStack(alignment: .leading) {
                        Text(role.role)
                        fact("Key", role.keyID)
                        fact("Generation", role.generationDigest)
                        interval(role.interval)
                        Text("Supplied public record: \(presentation.generationRecords[index].count) bytes; provenance verification pending")
                    }
                }
            }
            Section("Exact initial allocation") {
                fact("Issuer", presentation.allocation.issuerID)
                fact("Enrolment", presentation.allocation.enrollmentID)
                fact("Capability", presentation.allocation.capabilityID)
                Text("Capability generation: \(presentation.allocation.capabilityGeneration)")
                fact("Grant", presentation.allocation.grantID)
                Text("Actual successor cap: \(presentation.allocation.successorCap)")
                interval(presentation.descriptor.interval)
                interval(presentation.allocation.issuerInterval)
                interval(presentation.allocation.enrollmentInterval)
                interval(presentation.allocation.capabilityInterval)
                interval(presentation.allocation.grantInterval)
            }
            Section("Peers and transaction") {
                fact("Proxenos peer", presentation.allocation.proxenosPeer)
                fact("Custodian peer", presentation.allocation.custodianPeer)
                fact("Witness peer", presentation.allocation.witnessPeer)
                fact("Transport issuer pin", presentation.allocation.transportPin)
                fact("Bootstrap operation", presentation.allocation.operation)
                fact("Challenge", presentation.allocation.challenge)
                Text(ContinuitySpecification.coordinate)
                fact("Specification", ContinuitySpecification.digest)
                fact("Profile P", ContinuitySpecification.profile)
                fact("Profile A", ContinuitySpecification.callerProfile)
            }
        }
        .navigationTitle("Continuity approval review")
    }
    private func fact(_ title: String, _ value: Data) -> some View {
        LabeledContent(title, value: value.map { String(format: "%02x", $0) }.joined())
    }
    private func interval(_ value: ContinuityInterval) -> some View {
        Text("UTC seconds: \(value.notBefore) ≤ time < \(value.notAfter)")
    }
}
