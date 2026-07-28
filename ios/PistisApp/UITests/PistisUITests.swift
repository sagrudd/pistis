import XCTest

@MainActor
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

    func testGitHubEnrolmentExplainsItsDisabledSecurityBoundary() {
        let application = XCUIApplication()
        application.launch()
        if application.buttons["Continue to Pistis"].exists {
            application.buttons["Continue to Pistis"].tap()
        }

        XCTAssertTrue(application.staticTexts["GitHub enrolment unavailable"].exists)
        XCTAssertTrue(application.buttons["Enrol with GitHub"].exists)
        XCTAssertFalse(application.buttons["Enrol with GitHub"].isEnabled)
        XCTAssertTrue(application.staticTexts["Configuration missing"].exists)
    }

    func testScannerDoesNotPresentUnverifiedInputAsApproval() {
        let application = XCUIApplication()
        application.launch()
        if application.buttons["Continue to Pistis"].exists {
            application.buttons["Continue to Pistis"].tap()
        }
        application.tabBars.buttons["Scan"].tap()

        XCTAssertTrue(application.buttons["Start camera"].exists)
        XCTAssertTrue(application.staticTexts["Ready to scan"].exists)
        XCTAssertTrue(application.staticTexts["Passwordless approval unavailable"].exists)
        XCTAssertTrue(application.staticTexts["Installation authority"].exists)
        XCTAssertTrue(application.staticTexts["Production verifier"].exists)
        XCTAssertFalse(application.buttons["Approve and verify"].exists)
        XCTAssertFalse(application.buttons["Deny"].exists)
    }
}
