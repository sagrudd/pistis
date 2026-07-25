import XCTest

final class PistisUITests: XCTestCase {
    func testPrimaryNavigationIsVisible() {
        let application = XCUIApplication()
        application.launch()
        if application.buttons["Continue to Pistis"].exists {
            application.buttons["Continue to Pistis"].tap()
        }

        XCTAssertTrue(application.tabBars.buttons["Identities"].waitForExistence(timeout: 5))
        XCTAssertTrue(application.tabBars.buttons["Installations"].exists)
        XCTAssertTrue(application.tabBars.buttons["Scan"].exists)
        XCTAssertTrue(application.tabBars.buttons["History"].exists)
        XCTAssertTrue(application.tabBars.buttons["Settings"].exists)
    }

    func testApprovalKeepsEvidenceStatesSeparate() {
        let application = XCUIApplication()
        application.launch()
        if application.buttons["Continue to Pistis"].exists {
            application.buttons["Continue to Pistis"].tap()
        }
        application.tabBars.buttons["Scan"].tap()
        application.buttons["View approval design example"].tap()

        XCTAssertTrue(application.staticTexts["Local user"].exists)
        XCTAssertTrue(application.staticTexts["External identity"].exists)
        XCTAssertTrue(application.buttons["Approve and verify"].exists)
        XCTAssertTrue(application.buttons["Deny"].exists)
    }
}
