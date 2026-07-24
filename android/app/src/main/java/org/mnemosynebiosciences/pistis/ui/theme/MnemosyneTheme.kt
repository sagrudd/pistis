package org.mnemosynebiosciences.pistis.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

object MnColor {
    val Ink = Color(0xFF111111)
    val Canvas = Color(0xFFF6F7F5)
    val Raised = Color(0xFFFFFFFF)
    val Provenance = Color(0xFF1C2B0B)
    val MarkLight = Color(0xFFC7BFA8)
    val MarkDark = Color(0xFF4F5C29)
    val Action = Color(0xFF0F6B78)
    val ActionPressed = Color(0xFF0B5964)
    val Border = Color(0xFFD9E0E3)
    val Success = Color(0xFF28622B)
    val Warning = Color(0xFF6F5410)
    val Danger = Color(0xFF8A3C25)
    val OnBrand = Color.White
}

object MnSpacing {
    val x1 = 4.dp
    val x2 = 8.dp
    val x3 = 12.dp
    val x4 = 16.dp
    val x6 = 24.dp
    val x8 = 32.dp
}

object MnRadius {
    val small = 4.dp
    val medium = 8.dp
    val large = 12.dp
}

object MnMetrics {
    val minimumTarget = 48.dp
    val screenGutter = MnSpacing.x4
}

private val MnemosyneLightColors = lightColorScheme(
    primary = MnColor.Action,
    onPrimary = MnColor.OnBrand,
    primaryContainer = MnColor.Raised,
    onPrimaryContainer = MnColor.Ink,
    secondary = MnColor.Action,
    onSecondary = MnColor.OnBrand,
    background = MnColor.Canvas,
    onBackground = MnColor.Ink,
    surface = MnColor.Raised,
    onSurface = MnColor.Ink,
    error = MnColor.Danger,
    onError = MnColor.OnBrand,
    outline = MnColor.Border,
)

/**
 * Reviewed light-only Mnemosyne theme.
 *
 * Dynamic colour and dark appearance are intentionally unavailable until the
 * central design language defines those semantic roles.
 */
@Composable
fun PistisTheme(content: @Composable () -> Unit) {
    // Observe the setting so tests can prove that it does not silently alter
    // the reviewed palette.
    isSystemInDarkTheme()
    MaterialTheme(
        colorScheme = MnemosyneLightColors,
        content = content,
    )
}
