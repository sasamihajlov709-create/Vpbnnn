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
    primary = Color(0xFFF8BBD0),
    onPrimary = Color.Black,
    secondary = Color(0xFFF48FB1),
    onSecondary = Color.Black,
    tertiary = Color(0xFFF06292),
    onTertiary = Color.Black,
    background = Color.Black,
    onBackground = Color(0xFFF8BBD0),
    surface = Color.Black,
    onSurface = Color(0xFFF8BBD0),
    surfaceVariant = Color(0xFF111111),
    onSurfaceVariant = Color(0xFFF48FB1),
    outline = Color(0xFFF8BBD0)
)

@Composable
fun MyApplicationTheme(
    darkTheme: Boolean = true, // Force dark theme
    dynamicColor: Boolean = false, // Force our custom colors
    content: @Composable () -> Unit
) {
    MaterialTheme(colorScheme = AppColorScheme, typography = Typography, content = content)
}
