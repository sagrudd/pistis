import Foundation
import XCTest

@testable import Pistis

final class HistoricalUnknownSuccessorPresentationV1Tests: XCTestCase {
    func testPresentationBindsExactConsecutiveSuccessorTuple() throws {
        let presentation = try XCTUnwrap(Self.presentation())

        XCTAssertEqual(presentation.site, "site.example")
        XCTAssertEqual(presentation.vaultIdentity, "vault-17")
        XCTAssertEqual(presentation.consumedGeneration, 17)
        XCTAssertEqual(presentation.proposedGeneration, 18)
        XCTAssertEqual(presentation.freshHostKeyDigest, "sha256:" + String(repeating: "a", count: 64))
        XCTAssertEqual(presentation.purposeClaim, "unverified-fixture-purpose")
        XCTAssertEqual(presentation.requestIDClaim, "request-42")
        XCTAssertEqual(presentation.contractRevisionClaim, "fixture-revision-3")
    }

    func testPresentationRejectsReplaySkipAndMalformedBinding() {
        XCTAssertNil(Self.presentation(proposedGeneration: 17))
        XCTAssertNil(Self.presentation(proposedGeneration: 19))
        XCTAssertNil(Self.presentation(consumedGeneration: 0, proposedGeneration: 1))
        XCTAssertNil(Self.presentation(
            consumedGeneration: UInt64.max, proposedGeneration: 0
        ))
        XCTAssertNil(Self.presentation(freshHostKeyDigest: "sha256:abcd"))
        XCTAssertNil(Self.presentation(
            freshHostKeyDigest: "sha256:" + String(repeating: "A", count: 64)
        ))
        XCTAssertNil(Self.presentation(
            freshHostKeyDigest: "sha256:" + String(repeating: "a", count: 63) + "ａ"
        ))
        XCTAssertNil(Self.presentation(purposeClaim: ""))
        XCTAssertNil(Self.presentation(requestIDClaim: ""))
        XCTAssertNil(Self.presentation(contractRevisionClaim: ""))
    }

    func testReviewIsReadOnlyAndKeepsLegacyHandlersOut() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("Sources/App/HistoricalUnknownSuccessorReviewV1.swift"),
            encoding: .utf8
        )

        XCTAssertTrue(source.contains("Historical readiness: UNKNOWN"))
        XCTAssertTrue(source.contains("the displayed values are claims only"))
        XCTAssertTrue(source.contains("No historical readiness was inferred"))
        XCTAssertTrue(source.contains("proposal.site"))
        XCTAssertTrue(source.contains("proposal.vaultIdentity"))
        XCTAssertTrue(source.contains("proposal.consumedGeneration"))
        XCTAssertTrue(source.contains("proposal.proposedGeneration"))
        XCTAssertTrue(source.contains("proposal.freshHostKeyDigest"))
        XCTAssertTrue(source.contains("proposal.purposeClaim"))
        XCTAssertTrue(source.contains("proposal.requestIDClaim"))
        XCTAssertTrue(source.contains("proposal.contractRevisionClaim"))
        XCTAssertFalse(source.contains("FaceID"))
        XCTAssertFalse(source.contains("approve()"))
        XCTAssertFalse(source.contains("BaseCampVaultSuccessor"))
        XCTAssertFalse(source.contains("SiteX509"))
    }

    private static func presentation(
        site: String = "site.example",
        vaultIdentity: String = "vault-17",
        consumedGeneration: UInt64 = 17,
        proposedGeneration: UInt64 = 18,
        freshHostKeyDigest: String = "sha256:" + String(repeating: "a", count: 64),
        purposeClaim: String = "unverified-fixture-purpose",
        requestIDClaim: String = "request-42",
        contractRevisionClaim: String = "fixture-revision-3"
    ) -> HistoricalUnknownSuccessorPresentationV1? {
        HistoricalUnknownSuccessorPresentationV1(
            site: site,
            vaultIdentity: vaultIdentity,
            consumedGeneration: consumedGeneration,
            proposedGeneration: proposedGeneration,
            freshHostKeyDigest: freshHostKeyDigest,
            purposeClaim: purposeClaim,
            requestIDClaim: requestIDClaim,
            contractRevisionClaim: contractRevisionClaim
        )
    }
}
