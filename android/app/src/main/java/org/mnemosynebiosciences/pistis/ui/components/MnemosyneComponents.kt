package org.mnemosynebiosciences.pistis.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.mnemosynebiosciences.pistis.R
import org.mnemosynebiosciences.pistis.presentation.EvidenceStatus
import org.mnemosynebiosciences.pistis.presentation.StatusKind
import org.mnemosynebiosciences.pistis.ui.theme.MnColor
import org.mnemosynebiosciences.pistis.ui.theme.MnMetrics
import org.mnemosynebiosciences.pistis.ui.theme.MnRadius
import org.mnemosynebiosciences.pistis.ui.theme.MnSpacing

@Composable
fun MnSectionHeading(title: String, orientation: String? = null) {
    Column(
        modifier = Modifier.semantics(mergeDescendants = true) { heading() },
        verticalArrangement = Arrangement.spacedBy(MnSpacing.x2),
    ) {
        Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
        if (orientation != null) {
            Text(orientation, style = MaterialTheme.typography.bodyLarge)
        }
    }
}

@Composable
fun MnStatusLabel(status: EvidenceStatus, modifier: Modifier = Modifier) {
    val color = when (status.kind) {
        StatusKind.SUCCESS -> MnColor.Success
        StatusKind.WARNING -> MnColor.Warning
        StatusKind.DANGER -> MnColor.Danger
        StatusKind.NEUTRAL -> MnColor.Ink
    }
    val prefix = when (status.kind) {
        StatusKind.SUCCESS -> "Confirmed"
        StatusKind.WARNING -> "Attention"
        StatusKind.DANGER -> "Blocked"
        StatusKind.NEUTRAL -> "Information"
    }
    Text(
        text = status.words,
        color = color,
        fontWeight = FontWeight.SemiBold,
        style = MaterialTheme.typography.bodyMedium,
        modifier = modifier.semantics {
            contentDescription = "$prefix: ${status.words}"
        },
    )
}

@Composable
fun MnPanel(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(MnRadius.large),
        colors = CardDefaults.cardColors(containerColor = MnColor.Raised),
        border = BorderStroke(MnSpacing.x1 / 4, MnColor.Border),
    ) {
        Column(
            modifier = Modifier.padding(MnSpacing.x4),
            verticalArrangement = Arrangement.spacedBy(MnSpacing.x3),
        ) {
            content()
        }
    }
}

@Composable
fun MnEvidenceRow(label: String, value: String, monospaced: Boolean = false) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .semantics(mergeDescendants = true) {
                contentDescription = "$label: $value"
            },
        verticalArrangement = Arrangement.spacedBy(MnSpacing.x1),
    ) {
        Text(label, style = MaterialTheme.typography.labelMedium)
        Text(
            value,
            style = MaterialTheme.typography.bodyLarge,
            fontFamily = if (monospaced) FontFamily.Monospace else FontFamily.Default,
        )
    }
}

/**
 * Grouped trust evidence that remains readable by TalkBack and selectable for
 * exact out-of-band comparison.
 */
@Composable
fun MnFingerprintEvidence(label: String, value: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .semantics(mergeDescendants = true) {
                contentDescription = "$label: $value"
            },
        verticalArrangement = Arrangement.spacedBy(MnSpacing.x1),
    ) {
        Text(label, style = MaterialTheme.typography.labelMedium)
        SelectionContainer {
            Text(
                value,
                style = MaterialTheme.typography.bodyLarge,
                fontFamily = FontFamily.Monospace,
            )
        }
    }
}

@Composable
fun MnPrimaryButton(
    title: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    Button(
        onClick = onClick,
        enabled = enabled,
        interactionSource = interactionSource,
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = MnMetrics.minimumTarget),
        shape = RoundedCornerShape(MnRadius.medium),
        colors = ButtonDefaults.buttonColors(
            containerColor = if (isPressed) MnColor.ActionPressed else MnColor.Action,
            contentColor = MnColor.OnBrand,
            disabledContainerColor = MnColor.Border,
            disabledContentColor = MnColor.Ink,
        ),
    ) {
        Text(title, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun MnEmptyState(
    title: String,
    explanation: String,
    actionTitle: String? = null,
    onAction: (() -> Unit)? = null,
) {
    MnPanel {
        Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(explanation)
        if (actionTitle != null && onAction != null) {
            MnPrimaryButton(actionTitle, onAction)
        }
    }
}

@Composable
fun MnFailureState(
    title: String,
    explanation: String,
    safeAction: String,
    onSafeAction: () -> Unit,
) {
    MnPanel {
        MnStatusLabel(EvidenceStatus(title, StatusKind.DANGER))
        Text(explanation)
        MnPrimaryButton(safeAction, onSafeAction)
    }
}

@Composable
fun MnProvenance() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .semantics(mergeDescendants = true) {
                contentDescription = "Pistis, by Mnemosyne Biosciences"
            }
            .padding(MnSpacing.x4),
        verticalArrangement = Arrangement.spacedBy(MnSpacing.x2),
    ) {
        Image(
            painter = painterResource(R.drawable.mnemosyne_biosciences_logo_master_mono),
            contentDescription = null,
            contentScale = ContentScale.Fit,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(max = 96.dp)
                .background(MnColor.Raised, RoundedCornerShape(MnRadius.medium))
                .padding(MnSpacing.x2),
        )
        Text(
            "Pistis",
            color = MnColor.OnBrand,
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Composable
fun MnResourceRow(
    accessibilityLabel: String,
    content: @Composable RowScope.() -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = MnMetrics.minimumTarget)
            .semantics(mergeDescendants = true) {
                contentDescription = accessibilityLabel
            }
            .padding(vertical = MnSpacing.x3),
        horizontalArrangement = Arrangement.spacedBy(MnSpacing.x3),
        verticalAlignment = Alignment.Top,
        content = content,
    )
}

@Composable
fun EvidenceValue(text: String, color: Color = MnColor.Ink) {
    Text(
        text,
        color = color,
        maxLines = 3,
        overflow = TextOverflow.Ellipsis,
        style = MaterialTheme.typography.bodyMedium,
    )
}
