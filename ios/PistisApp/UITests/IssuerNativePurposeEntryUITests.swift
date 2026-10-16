import XCTest

@MainActor
final class IssuerNativePurposeEntryUITests: XCTestCase {
    func testSettingsReachesPlanReviewWithUnavailableNoticeBeforeAnyApproval() {
        let application = XCUIApplication()
        application.launch()
        if application.buttons["Continue to Pistis"].exists {
            application.buttons["Continue to Pistis"].tap()
        }
        let settings = application.tabBars.buttons["Settings"]
        XCTAssertTrue(settings.waitForExistence(timeout: 5))
        settings.tap()
        let entry = application.buttons["settings-native-issuer-installation"]
        XCTAssertTrue(entry.waitForExistence(timeout: 5))
        for _ in 0..<4 where !entry.isHittable { application.swipeUp() }
        XCTAssertTrue(entry.isHittable)
        entry.tap()
        XCTAssertTrue(application.staticTexts["Setup unavailable"].waitForExistence(timeout: 5))
        XCTAssertFalse(application.buttons["Approve installation with Face ID"].exists)
        let review = application.buttons["native-purpose-review-plan"]
        XCTAssertTrue(review.exists)
        for _ in 0..<4 where !review.isHittable { application.swipeUp() }
        XCTAssertTrue(review.isHittable)
        review.tap()
        XCTAssertTrue(application.buttons["Open installation plan"].waitForExistence(timeout: 5))
        XCTAssertFalse(application.buttons["Approve installation with Face ID"].exists)
    }
}
