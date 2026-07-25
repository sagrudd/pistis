package org.mnemosynebiosciences.pistis.presentation

import androidx.compose.ui.test.assertHasNoClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Rule
import org.junit.Test
import org.mnemosynebiosciences.pistis.ui.theme.PistisTheme

class PistisRootTest {
    @get:Rule
    val compose = createComposeRule()

    @Test
    fun onboardingStatesEvidenceAndClaimBoundaries() {
        compose.setContent {
            PistisTheme {
                PistisRoot(PistisUiState.empty())
            }
        }

        compose.onNodeWithText("Evidence-led approvals").assertIsDisplayed()
        compose.onNodeWithText(
            "Development source: device assurance and distribution are not yet verified",
        ).assertIsDisplayed()
    }

    @Test
    fun productionShellUsesHonestEmptyStates() {
        compose.setContent {
            PistisTheme {
                PistisRoot(PistisUiState.empty().copy(hasCompletedOnboarding = true))
            }
        }

        compose.onNodeWithText("No enrolled identities").assertIsDisplayed()
        compose.onNodeWithText("Installations").performClick()
        compose.onNodeWithText("No paired installations").assertIsDisplayed()
        compose.onNodeWithText("History").performClick()
        compose.onNodeWithText("No local history").assertIsDisplayed()
    }

    @Test
    fun scannerDoesNotClaimCameraIntegration() {
        compose.setContent {
            PistisTheme {
                PistisRoot(PistisUiState.empty().copy(hasCompletedOnboarding = true))
            }
        }

        compose.onNodeWithText("Scan").performClick()
        compose.onNodeWithText("Camera integration: Not configured").assertIsDisplayed()
        compose.onNodeWithText(
            "This build does not claim a working scanner. No camera frames are acquired, stored, or logged.",
        ).assertIsDisplayed()
    }

    @Test
    fun installationEvidenceIsInformationalAndIncludesFingerprint() {
        val installation = InstallationSummary(
            stableId = "installation-1",
            name = "Synoptikon test",
            localAlias = "Test installation",
            fingerprint = "7A31 9C42 0F88 1B6D",
            trustStatus = EvidenceStatus("Trust: Needs review", StatusKind.WARNING),
            lastUsed = null,
        )
        compose.setContent {
            PistisTheme {
                PistisRoot(
                    PistisUiState.empty().copy(
                        hasCompletedOnboarding = true,
                        installations = listOf(installation),
                    ),
                )
            }
        }

        compose.onNodeWithText("Installations").performClick()
        compose.onNodeWithContentDescription(
            "Synoptikon test, Trust: Needs review, " +
                "fingerprint 7A31 9C42 0F88 1B6D, last used not observed",
        )
            .assertIsDisplayed()
            .assertHasNoClickAction()
    }
}
