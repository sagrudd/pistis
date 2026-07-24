package org.mnemosynebiosciences.pistis.presentation.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import org.mnemosynebiosciences.pistis.presentation.ApprovalRequestPresentation
import org.mnemosynebiosciences.pistis.presentation.ApprovalResultFacts
import org.mnemosynebiosciences.pistis.ui.components.MnEvidenceRow
import org.mnemosynebiosciences.pistis.ui.components.MnFingerprintEvidence
import org.mnemosynebiosciences.pistis.ui.components.MnPanel
import org.mnemosynebiosciences.pistis.ui.components.MnPrimaryButton
import org.mnemosynebiosciences.pistis.ui.components.MnSectionHeading
import org.mnemosynebiosciences.pistis.ui.components.MnStatusLabel
import org.mnemosynebiosciences.pistis.ui.theme.MnColor
import org.mnemosynebiosciences.pistis.ui.theme.MnMetrics
import org.mnemosynebiosciences.pistis.ui.theme.MnSpacing

/**
 * Focused review surface. The caller owns the deterministic ceremony and must
 * not treat [onApprove] as a signature or verification result.
 */
@Composable
fun ApprovalReviewScreen(
    request: ApprovalRequestPresentation,
    onApprove: () -> Unit,
    onDeny: () -> Unit,
    onCancel: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(MnMetrics.screenGutter),
        verticalArrangement = Arrangement.spacedBy(MnSpacing.x4),
    ) {
        TextButton(onClick = onCancel) { Text("Cancel") }
        MnSectionHeading(request.action, request.subject)
        MnStatusLabel(request.trustStatus)
        MnPanel {
            MnEvidenceRow("Installation", request.installation)
            HorizontalDivider(color = MnColor.Border)
            MnEvidenceRow("Local user", request.localUser)
            HorizontalDivider(color = MnColor.Border)
            MnEvidenceRow("External identity", request.externalIdentity)
            HorizontalDivider(color = MnColor.Border)
            MnFingerprintEvidence("Installation fingerprint", request.fingerprint)
            HorizontalDivider(color = MnColor.Border)
            MnEvidenceRow("Expires in", request.expiry)
            HorizontalDivider(color = MnColor.Border)
            MnEvidenceRow("Request route", request.route)
        }
        Text(
            "Approving requests local verification before Pistis may produce a device signature. " +
                "Approval alone does not mean the request was signed, delivered, verified, or accepted.",
        )
        MnPrimaryButton("Approve and verify", onApprove)
        TextButton(onClick = onDeny) {
            Text("Deny", color = MnColor.Danger)
        }
    }
}

@Composable
fun ApprovalResultScreen(facts: ApprovalResultFacts, onDone: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(MnMetrics.screenGutter),
        verticalArrangement = Arrangement.spacedBy(MnSpacing.x6),
    ) {
        MnSectionHeading(
            "Result",
            "Each line is a separate observed fact. One successful fact does not imply another.",
        )
        MnPanel {
            MnStatusLabel(facts.humanDecision)
            MnStatusLabel(facts.localAuthentication)
            MnStatusLabel(facts.deviceSignature)
            MnStatusLabel(facts.transfer)
            MnStatusLabel(facts.serverVerification)
        }
        MnPrimaryButton("Done", onDone)
    }
}
