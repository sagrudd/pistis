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
import org.mnemosynebiosciences.pistis.presentation.IdentitySummary
import org.mnemosynebiosciences.pistis.ui.components.MnEmptyState
import org.mnemosynebiosciences.pistis.ui.components.MnResourceRow
import org.mnemosynebiosciences.pistis.ui.components.MnSectionHeading
import org.mnemosynebiosciences.pistis.ui.components.MnStatusLabel
import org.mnemosynebiosciences.pistis.ui.theme.MnColor
import org.mnemosynebiosciences.pistis.ui.theme.MnMetrics
import org.mnemosynebiosciences.pistis.ui.theme.MnSpacing

@Composable
fun IdentitiesScreen(identities: List<IdentitySummary>) {
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
                    "Identities",
                    "Review the external accounts that establish who you are during enrolment.",
                )
            }
        }
        if (identities.isEmpty()) {
            item {
                MnEmptyState(
                    "No enrolled identities",
                    "Provider enrolment requires a configured Pistis broker and has not run on this device.",
                )
            }
        } else {
            items(identities, key = { it.stableId }) { identity ->
                MnResourceRow(
                    accessibilityLabel =
                        "${identity.provider}, ${identity.displayName}, ${identity.status.words}",
                ) {
                    Column(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(MnSpacing.x1),
                    ) {
                        Text(identity.displayName)
                        Text(identity.provider)
                        Text(identity.stableSubject)
                        MnStatusLabel(identity.status)
                    }
                }
                HorizontalDivider(color = MnColor.Border)
            }
        }
    }
}
