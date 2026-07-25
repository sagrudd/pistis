package org.mnemosynebiosciences.pistis

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import org.mnemosynebiosciences.pistis.presentation.PistisRoot
import org.mnemosynebiosciences.pistis.presentation.PistisUiState
import org.mnemosynebiosciences.pistis.ui.theme.PistisTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            PistisTheme {
                // Production composition starts without demonstration trust or
                // evidence. Platform repositories will replace this empty state.
                PistisRoot(state = PistisUiState.empty())
            }
        }
    }
}
