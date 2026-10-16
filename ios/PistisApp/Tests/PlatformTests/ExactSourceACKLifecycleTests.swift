import Foundation
import PistisCore
import XCTest
import UIKit
@testable import Pistis

final class ExactSourceACKLifecycleTests: XCTestCase {
    func testBackgroundThenForegroundIsStickyDuringEveryPreparedInterval() throws {
        for interval in ["preparation-await", "display", "FaceID-await", "delivery"] {
            let center = NotificationCenter()
            let state = ExactSourceACKLifecycle(center: center, initialWall: Date(timeIntervalSince1970: 100))
            try state.observe(wall: Date(timeIntervalSince1970: 101))
            center.post(name: UIApplication.didEnterBackgroundNotification, object: nil)
            center.post(name: UIApplication.didBecomeActiveNotification, object: nil)
            var invocations = 0
            XCTAssertThrowsError(try {
                try state.observe(wall: Date(timeIntervalSince1970: 102))
                invocations += 1
            }(), interval)
            XCTAssertEqual(invocations, 0, interval)
        }
    }
    func testExplicitDisplayCancellationAndRollbackAboveStartNeverRestore() throws {
        let state = ExactSourceACKLifecycle(center: NotificationCenter(), initialWall: Date(timeIntervalSince1970: 100))
        try state.observe(wall: Date(timeIntervalSince1970: 105))
        XCTAssertThrowsError(try state.observe(wall: Date(timeIntervalSince1970: 103)))
        XCTAssertThrowsError(try state.observe(wall: Date(timeIntervalSince1970: 106)))
        let dismissed = ExactSourceACKLifecycle(center: NotificationCenter(), initialWall: Date(timeIntervalSince1970: 100))
        dismissed.invalidate()
        XCTAssertThrowsError(try dismissed.observe(wall: Date(timeIntervalSince1970: 101)))
    }
    func testBodyAndActionIssueAndExclusiveEndsAreCheckedByActualLifecycleHelper() throws {
        for seconds in [109.0, 111.0, 119.0, 125.0] {
            let state = ExactSourceACKLifecycle(center: NotificationCenter(), initialWall: Date(timeIntervalSince1970: 100))
            XCTAssertThrowsError(try state.validate(issuedAt: 110, expiresAt: 125,
                actionIssuedAt: 112, actionExpiresAt: 120, taskExpiresAt: 119,
                wall: Date(timeIntervalSince1970: seconds)))
            XCTAssertThrowsError(try state.observe(wall: Date(timeIntervalSince1970: 130)))
        }
        let live = ExactSourceACKLifecycle(center: NotificationCenter(), initialWall: Date(timeIntervalSince1970: 100))
        XCTAssertNoThrow(try live.validate(issuedAt: 110, expiresAt: 125, actionIssuedAt: 112,
            actionExpiresAt: 120, taskExpiresAt: 119, wall: Date(timeIntervalSince1970: 118)))
    }
}
