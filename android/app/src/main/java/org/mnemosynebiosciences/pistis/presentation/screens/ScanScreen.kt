package org.mnemosynebiosciences.pistis.presentation.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import org.mnemosynebiosciences.pistis.presentation.EvidenceStatus
import org.mnemosynebiosciences.pistis.presentation.StatusKind
import org.mnemosynebiosciences.pistis.ui.components.MnPanel
import org.mnemosynebiosciences.pistis.ui.components.MnSectionHeading
import org.mnemosynebiosciences.pistis.ui.components.MnStatusLabel
import org.mnemosynebiosciences.pistis.ui.theme.MnColor
import org.mnemosynebiosciences.pistis.ui.theme.MnMetrics
import org.mnemosynebiosciences.pistis.ui.theme.MnRadius
import org.mnemosynebiosciences.pistis.ui.theme.MnSpacing

@Composable
fun ScanScreen() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(MnMetrics.screenGutter),
        verticalArrangement = Arrangement.spacedBy(MnSpacing.x6),
    ) {
        MnSectionHeading(
            "Scan",
            "Acquire a Pistis request only after the reviewed camera and protocol adapters are available.",
        )
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(1f)
                .background(MnColor.Ink, RoundedCornerShape(MnRadius.large))
                .semantics {
                    contentDescription = "Camera unavailable. Scanner integration is not configured."
                },
            contentAlignment = Alignment.Center,
        ) {
            Text("Camera unavailable", color = MnColor.OnBrand)
        }
        MnPanel {
            MnStatusLabel(
                EvidenceStatus("Camera integration: Not configured", StatusKind.WARNING),
            )
            Text(
                "This build does not claim a working scanner. No camera frames are acquired, stored, or logged.",
            )
            Text(
                "Production approval remains blocked until challenge validation and signing adapters are connected.",
            )
        }
    }
}
