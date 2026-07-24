package org.mnemosynebiosciences.pistis.presentation.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import org.mnemosynebiosciences.pistis.presentation.EvidenceStatus
import org.mnemosynebiosciences.pistis.presentation.StatusKind
import org.mnemosynebiosciences.pistis.ui.components.MnPanel
import org.mnemosynebiosciences.pistis.ui.components.MnPrimaryButton
import org.mnemosynebiosciences.pistis.ui.components.MnProvenance
import org.mnemosynebiosciences.pistis.ui.components.MnSectionHeading
import org.mnemosynebiosciences.pistis.ui.components.MnStatusLabel
import org.mnemosynebiosciences.pistis.ui.theme.MnColor
import org.mnemosynebiosciences.pistis.ui.theme.MnMetrics
import org.mnemosynebiosciences.pistis.ui.theme.MnSpacing

@Composable
fun OnboardingScreen(onContinue: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MnColor.Canvas)
            .windowInsetsPadding(WindowInsets.safeDrawing)
            .verticalScroll(rememberScrollState())
            .padding(MnMetrics.screenGutter),
        verticalArrangement = Arrangement.spacedBy(MnSpacing.x6),
    ) {
        Column(Modifier.fillMaxWidth().background(MnColor.Provenance)) {
            MnProvenance()
        }
        MnSectionHeading(
            "Evidence-led approvals",
            "Pistis keeps human intent, local verification, signature production, transfer, and server verification as separate facts.",
        )
        MnPanel {
            Text("Device signing keys are intended to remain non-exportable in Android Keystore.")
            Text("Every signing operation requires fresh local user verification.")
            Text("GitHub passkeys remain with the system browser and credential provider.")
        }
        MnStatusLabel(
            EvidenceStatus(
                "Development source: device assurance and distribution are not yet verified",
                StatusKind.WARNING,
            ),
        )
        MnPrimaryButton("Continue to Pistis", onContinue)
    }
}
