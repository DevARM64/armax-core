// Tema de ARMax: panel de minería oscuro (con variante clara) y acento cian (el del logo).
package org.armax.app

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

private val DarkColors: ColorScheme = darkColorScheme(
    primary = Color(0xFF22D3FF),
    onPrimary = Color(0xFF00232E),
    primaryContainer = Color(0xFF07303D),
    onPrimaryContainer = Color(0xFFB3EEFF),
    secondary = Color(0xFF3DDC84),
    onSecondary = Color(0xFF00391C),
    background = Color(0xFF0B0F14),
    onBackground = Color(0xFFE6EAF0),
    surface = Color(0xFF121821),
    onSurface = Color(0xFFE6EAF0),
    surfaceVariant = Color(0xFF1A2230),
    onSurfaceVariant = Color(0xFF9AA6B8),
    outline = Color(0xFF2B3647),
    error = Color(0xFFFF6B7A),
    onError = Color(0xFF3A0008),
)

private val LightColors: ColorScheme = lightColorScheme(
    primary = Color(0xFF007EA3),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFC7EEFF),
    onPrimaryContainer = Color(0xFF00303D),
    secondary = Color(0xFF1A8F4E),
    onSecondary = Color(0xFFFFFFFF),
    background = Color(0xFFF4F6F8),
    onBackground = Color(0xFF111820),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF111820),
    surfaceVariant = Color(0xFFE9EDF2),
    onSurfaceVariant = Color(0xFF55627A),
    outline = Color(0xFFCBD3DE),
    error = Color(0xFFC62840),
    onError = Color(0xFFFFFFFF),
)

@Composable
fun ArmaxTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (dark) DarkColors else LightColors, content = content)
}

/** Color de advertencia (ámbar), aparte del acento de la marca: avisos, límites y temperatura alta. */
@Composable
fun warningColor(): Color = if (MaterialTheme.colorScheme.background.red < 0.5f) Color(0xFFFFB020) else Color(0xFFB36B00)

/** Cifras grandes (saldo, velocidad): monoespaciadas para que no "bailen" al cambiar. */
val BigNumberStyle = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, fontSize = 30.sp)
val MidNumberStyle = TextStyle(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
