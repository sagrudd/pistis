package org.mnemosynebiosciences.pistis.presentation

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.NavigationRailItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.mnemosynebiosciences.pistis.presentation.screens.HistoryScreen
import org.mnemosynebiosciences.pistis.presentation.screens.IdentitiesScreen
import org.mnemosynebiosciences.pistis.presentation.screens.InstallationsScreen
import org.mnemosynebiosciences.pistis.presentation.screens.OnboardingScreen
import org.mnemosynebiosciences.pistis.presentation.screens.ScanScreen
import org.mnemosynebiosciences.pistis.presentation.screens.SettingsScreen
import org.mnemosynebiosciences.pistis.ui.theme.MnColor

@Composable
fun PistisRoot(state: PistisUiState) {
    var onboardingComplete by rememberSaveable { mutableStateOf(state.hasCompletedOnboarding) }
    if (!onboardingComplete) {
        OnboardingScreen(onContinue = { onboardingComplete = true })
        return
    }

    var destinationName by rememberSaveable {
        mutableStateOf(PistisDestination.IDENTITIES.name)
    }
    val destination = PistisDestination.valueOf(destinationName)

    BoxWithConstraints(Modifier.fillMaxSize()) {
        if (maxWidth >= 700.dp) {
            Row(Modifier.fillMaxSize().background(MnColor.Canvas)) {
                DestinationRail(destination) { destinationName = it.name }
                DestinationContent(
                    destination,
                    state,
                    Modifier.weight(1f).windowInsetsPadding(WindowInsets.safeDrawing),
                )
            }
        } else {
            Scaffold(
                containerColor = MnColor.Canvas,
                bottomBar = {
                    DestinationBar(destination) { destinationName = it.name }
                },
            ) { padding ->
                DestinationContent(destination, state, Modifier.padding(padding))
            }
        }
    }
}

@Composable
private fun DestinationContent(
    destination: PistisDestination,
    state: PistisUiState,
    modifier: Modifier,
) {
    Box(modifier.fillMaxSize().background(MnColor.Canvas)) {
        when (destination) {
            PistisDestination.IDENTITIES -> IdentitiesScreen(state.identities)
            PistisDestination.INSTALLATIONS -> InstallationsScreen(state.installations)
            PistisDestination.SCAN -> ScanScreen()
            PistisDestination.HISTORY -> HistoryScreen(state.history)
            PistisDestination.SETTINGS -> SettingsScreen(state.deviceSecurity)
        }
    }
}

@Composable
private fun DestinationBar(
    selected: PistisDestination,
    onSelected: (PistisDestination) -> Unit,
) {
    NavigationBar(containerColor = MnColor.Raised) {
        PistisDestination.entries.forEach { destination ->
            NavigationBarItem(
                selected = selected == destination,
                onClick = { onSelected(destination) },
                icon = { DestinationGlyph(destination, selected == destination) },
                label = { Text(destination.label) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = MnColor.Action,
                    selectedTextColor = MnColor.Ink,
                    indicatorColor = MnColor.Raised,
                    unselectedIconColor = MnColor.Ink,
                    unselectedTextColor = MnColor.Ink,
                    disabledIconColor = MnColor.Border,
                    disabledTextColor = MnColor.Ink,
                ),
            )
        }
    }
}

@Composable
private fun DestinationRail(
    selected: PistisDestination,
    onSelected: (PistisDestination) -> Unit,
) {
    NavigationRail(containerColor = MnColor.Raised) {
        PistisDestination.entries.forEach { destination ->
            NavigationRailItem(
                selected = selected == destination,
                onClick = { onSelected(destination) },
                icon = { DestinationGlyph(destination, selected == destination) },
                label = { Text(destination.label) },
                colors = NavigationRailItemDefaults.colors(
                    selectedIconColor = MnColor.Action,
                    selectedTextColor = MnColor.Ink,
                    indicatorColor = MnColor.Raised,
                    unselectedIconColor = MnColor.Ink,
                    unselectedTextColor = MnColor.Ink,
                    disabledIconColor = MnColor.Border,
                    disabledTextColor = MnColor.Ink,
                ),
            )
        }
    }
}

@Composable
private fun DestinationGlyph(destination: PistisDestination, isSelected: Boolean) {
    Text(
        destination.shortLabel,
        modifier = Modifier
            .clearAndSetSemantics { }
            .semantics {
                contentDescription = destination.label
                selected = isSelected
            },
    )
}
