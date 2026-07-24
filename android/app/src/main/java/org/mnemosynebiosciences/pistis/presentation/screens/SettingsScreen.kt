package org.mnemosynebiosciences.pistis.presentation.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import org.mnemosynebiosciences.pistis.presentation.DeviceSecurityPresentation
import org.mnemosynebiosciences.pistis.presentation.EvidenceStatus
import org.mnemosynebiosciences.pistis.presentation.StatusKind
import org.mnemosynebiosciences.pistis.ui.components.MnEvidenceRow
import org.mnemosynebiosciences.pistis.ui.components.MnPanel
import org.mnemosynebiosciences.pistis.ui.components.MnProvenance
import org.mnemosynebiosciences.pistis.ui.components.MnSectionHeading
import org.mnemosynebiosciences.pistis.ui.components.MnStatusLabel
import org.mnemosynebiosciences.pistis.ui.theme.MnColor
import org.mnemosynebiosciences.pistis.ui.theme.MnMetrics
import org.mnemosynebiosciences.pistis.ui.theme.MnSpacing

@Composable
fun SettingsScreen(security: DeviceSecurityPresentation) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(MnMetrics.screenGutter),
        verticalArrangement = Arrangement.spacedBy(MnSpacing.x6),
    ) {
        MnSectionHeading("Settings", "Security evidence and application information.")
        MnSectionHeading("Device security")
        MnPanel {
            MnStatusLabel(security.signingKey)
            HorizontalDivider(color = MnColor.Border)
            MnStatusLabel(security.authenticationPolicy)
            HorizontalDivider(color = MnColor.Border)
            MnStatusLabel(security.securityLevel)
            HorizontalDivider(color = MnColor.Border)
            MnStatusLabel(security.attestation)
            Text(
                "A locally reported StrongBox or trusted-environment property is not validated remote attestation.",
            )
        }
        DiagnosticsSection()
        PrivacySection()
        AboutSection()
    }
}

@Composable
private fun DiagnosticsSection() {
    MnSectionHeading("Diagnostics")
    MnPanel {
        MnStatusLabel(
            EvidenceStatus(
                "Protocol: Production interoperability not claimed",
                StatusKind.WARNING,
            ),
        )
        MnStatusLabel(
            EvidenceStatus("Camera: Not configured", StatusKind.NEUTRAL),
        )
        MnStatusLabel(
            EvidenceStatus("Local discovery: Not configured", StatusKind.NEUTRAL),
        )
        MnStatusLabel(
            EvidenceStatus("Play distribution: Not verified", StatusKind.WARNING),
        )
    }
}

@Composable
private fun PrivacySection() {
    MnSectionHeading("Privacy and legal")
    MnPanel {
        Text("Private signing-key bytes must never leave Android Keystore.")
        Text("Camera frames and complete challenges are not retained.")
        Text("Provider access tokens are not stored by the application.")
        Text("Local history is informational and is not an authoritative evidence store.")
    }
}

@Composable
private fun AboutSection() {
    MnSectionHeading("About")
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(MnSpacing.x3),
    ) {
        // The only provenance treatment in the post-onboarding shell.
        Column(Modifier.fillMaxWidth().background(MnColor.Provenance)) {
            MnProvenance()
        }
        MnPanel {
            MnEvidenceRow("Application", "Pistis")
            HorizontalDivider(color = MnColor.Border)
            MnEvidenceRow("Version", "Development build")
            HorizontalDivider(color = MnColor.Border)
            Text(
                "Local-first cryptographic identity, authentication, approval, and evidence for scientific computing.",
            )
        }
    }
}
