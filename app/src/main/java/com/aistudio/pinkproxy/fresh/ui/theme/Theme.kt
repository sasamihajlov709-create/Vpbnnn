package com.aistudio.pinkproxy.fresh.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

import androidx.compose.ui.graphics.Color

private val AppColorScheme = darkColorScheme(
    primary = GentleLightPink,
    onPrimary = PureBlack,
    secondary = GentleMediumPink,
    onSecondary = PureBlack,
    tertiary = GentleDarkPink,
    onTertiary = PureBlack,
    background = PureBlack,
    onBackground = GentleLightPink,
    surface = PureBlack,
    onSurface = GentleLightPink,
    surfaceVariant = DarkGreyBlack,
    onSurfaceVariant = GentleMediumPink,
    outline = GentleLightPink
)

@Composable
fun MyApplicationTheme(
    darkTheme: Boolean = true, // Force dark theme
    dynamicColor: Boolean = false, // Force our custom colors
    content: @Composable () -> Unit
) {
    MaterialTheme(colorScheme = AppColorScheme, typography = Typography, content = content)
}
