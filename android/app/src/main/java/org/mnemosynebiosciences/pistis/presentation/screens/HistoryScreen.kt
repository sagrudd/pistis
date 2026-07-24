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
import org.mnemosynebiosciences.pistis.presentation.LocalHistorySummary
import org.mnemosynebiosciences.pistis.ui.components.MnEmptyState
import org.mnemosynebiosciences.pistis.ui.components.MnResourceRow
import org.mnemosynebiosciences.pistis.ui.components.MnSectionHeading
import org.mnemosynebiosciences.pistis.ui.components.MnStatusLabel
import org.mnemosynebiosciences.pistis.ui.theme.MnColor
import org.mnemosynebiosciences.pistis.ui.theme.MnMetrics
import org.mnemosynebiosciences.pistis.ui.theme.MnSpacing

@Composable
fun HistoryScreen(events: List<LocalHistorySummary>) {
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
                    "History",
                    "This device’s observations, not an installation’s authoritative audit record.",
                )
            }
        }
        if (events.isEmpty()) {
            item {
                MnEmptyState(
                    "No local history",
                    "Approvals and denials observed on this device will appear here. " +
                        "This is not the authoritative audit record.",
                )
            }
        } else {
            items(events, key = { it.stableId }) { event ->
                MnResourceRow(
                    accessibilityLabel =
                        "${event.action}, ${event.installation}, " +
                            "${event.facts.humanDecision.words}, ${event.observedAt}",
                ) {
                    Column(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(MnSpacing.x1),
                    ) {
                        Text(event.action)
                        Text(event.installation)
                        Text(event.observedAt)
                        MnStatusLabel(event.facts.humanDecision)
                    }
                }
                HorizontalDivider(color = MnColor.Border)
            }
        }
    }
}
