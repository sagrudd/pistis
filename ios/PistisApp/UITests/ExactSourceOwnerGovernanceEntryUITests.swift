import XCTest

@MainActor
final class ExactSourceOwnerGovernanceEntryUITests: XCTestCase {
    func testSettingsSourceReviewCannotOfferGovernanceOrSigningBeforeCurrentSubject() {
        let application = XCUIApplication()
        application.launch()
        if application.buttons["Continue to Pistis"].exists {
            application.buttons["Continue to Pistis"].tap()
        }
        let settings = application.tabBars.buttons["Settings"]
        XCTAssertTrue(settings.waitForExistence(timeout: 5))
        settings.tap()
        let entry = application.buttons["Review source qualification"]
        XCTAssertTrue(entry.waitForExistence(timeout: 5))
        for _ in 0..<4 where !entry.isHittable { application.swipeUp() }
        XCTAssertTrue(entry.isHittable)
        entry.tap()
        XCTAssertTrue(application.buttons["Load current request"].waitForExistence(timeout: 5))
        XCTAssertFalse(application.buttons["Review the required internal owner exception"].exists)
        XCTAssertFalse(application.buttons["Approve these exact details with Face ID"].exists)
    }
}
