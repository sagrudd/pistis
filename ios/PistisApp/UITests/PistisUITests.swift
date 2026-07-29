import XCTest

@MainActor
final class PistisUITests: XCTestCase {
    func testPrimarySurfacesPassNativeAccessibilityAudit() throws {
        let application = XCUIApplication()
        application.launch()

        if application.buttons["Continue to Pistis"].exists {
            try application.performAccessibilityAudit()
            application.buttons["Continue to Pistis"].tap()
        }

        for tab in ["Identities", "Installations", "Scan", "History", "Settings"] {
            let tabButton = application.tabBars.buttons[tab]
            XCTAssertTrue(tabButton.waitForExistence(timeout: 5), "\(tab) tab is unavailable")
            tabButton.tap()
            if tab == "Scan" {
                try application.performAccessibilityAudit(for: .all, handleScanTopViewportFinding)
                application.swipeUp()
                try application.performAccessibilityAudit(for: .all, handleScanBottomViewportFinding)
            } else if tab == "Settings" {
                application.swipeUp()
                try application.performAccessibilityAudit(for: .all, handleFrameworkAuditFinding)
            } else {
                try application.performAccessibilityAudit()
            }
        }
    }

    private func handleFrameworkAuditFinding(_ issue: XCUIAccessibilityAuditIssue) -> Bool {
        // Xcode 26.6 reports this standard NavigationLink label even though it
        // uses the scalable semantic body font.
        issue.auditType == .dynamicType && issue.element?.label == "About Pistis"
    }

    private func handleScanTopViewportFinding(_ issue: XCUIAccessibilityAuditIssue) -> Bool {
        let partlyObscuredAtBottom = [
            "Only bounded PISTIS1 version-2 challenge text is accepted. Request facts appear only after the enrolled installation key verifies the exact signed payload.",
            "Passwordless approval unavailable",
            "Camera",
        ]
        return issue.auditType == .contrast
            && partlyObscuredAtBottom.contains(issue.element?.label ?? "")
    }

    private func handleScanBottomViewportFinding(_ issue: XCUIAccessibilityAuditIssue) -> Bool {
        let partlyObscuredAtTop = [
            "Scan",
            "Ready to scan",
            "The accepted QR v2 and COSE verifier is available.",
            "Start camera",
        ]
        return issue.auditType == .contrast
            && partlyObscuredAtTop.contains(issue.element?.label ?? "")
    }

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
