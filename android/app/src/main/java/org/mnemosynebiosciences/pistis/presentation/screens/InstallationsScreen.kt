package org.mnemosynebiosciences.pistis.presentation.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import org.mnemosynebiosciences.pistis.presentation.InstallationSummary
import org.mnemosynebiosciences.pistis.ui.components.MnEmptyState
import org.mnemosynebiosciences.pistis.ui.components.MnFingerprintEvidence
import org.mnemosynebiosciences.pistis.ui.components.MnResourceRow
import org.mnemosynebiosciences.pistis.ui.components.MnSectionHeading
import org.mnemosynebiosciences.pistis.ui.components.MnStatusLabel
import org.mnemosynebiosciences.pistis.ui.theme.MnColor
import org.mnemosynebiosciences.pistis.ui.theme.MnMetrics
import org.mnemosynebiosciences.pistis.ui.theme.MnSpacing

@Composable
fun InstallationsScreen(installations: List<InstallationSummary>) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = MnMetrics.screenGutter),
        verticalArrangement = Arrangement.spacedBy(MnSpacing.x3),
    ) {
        item {
            Column(
                modifier = Modifier.padding(top = MnSpacing.x4),
                verticalArrangement = Arrangement.spacedBy(MnSpacing.x2),
            ) {
                MnSectionHeading(
                    "Installations",
                    "Remembered installations and the trust material you reviewed.",
                )
            }
        }
        if (installations.isEmpty()) {
            item {
                MnEmptyState(
                    "No paired installations",
                    "A verified pairing will record the installation and fingerprint here.",
                )
            }
        } else {
            items(installations, key = { it.stableId }) { installation ->
                MnResourceRow(
                    accessibilityLabel =
                        "${installation.name}, ${installation.trustStatus.words}, " +
                            "fingerprint ${installation.fingerprint}, " +
                            "last used ${installation.lastUsed ?: "not observed"}",
                ) {
                    Column(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(MnSpacing.x1),
                    ) {
                        Text(installation.name)
                        Text(installation.localAlias)
                        MnStatusLabel(installation.trustStatus)
                        MnFingerprintEvidence(
                            "Installation fingerprint",
                            installation.fingerprint,
                        )
                        Text("Last used ${installation.lastUsed ?: "Not observed"}")
                    }
                }
                HorizontalDivider(color = MnColor.Border)
            }
        }
    }
}
