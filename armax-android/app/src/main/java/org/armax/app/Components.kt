// Piezas visuales reutilizables del panel: logo, tarjetas, etiquetas de estado, gráfica y medidores.
package org.armax.app

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** Logo de la app (res/drawable-nodpi/ic_logo.png): para cambiarlo basta con reemplazar ese archivo. */
@Composable
fun Logo(size: Dp = 32.dp, modifier: Modifier = Modifier) {
    Image(painter = painterResource(R.drawable.ic_logo), contentDescription = null, modifier = modifier.size(size))
}

/** Tarjeta con borde fino, estilo panel. */
@Composable
fun Panel(modifier: Modifier = Modifier, title: String? = null, content: @Composable () -> Unit) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (title != null) {
                Text(title, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            content()
        }
    }
}

/** Etiqueta redondeada de estado. */
@Composable
fun Chip(text: String, color: Color, modifier: Modifier = Modifier) {
    Text(
        text,
        modifier = modifier
            .background(color.copy(alpha = 0.16f), RoundedCornerShape(50))
            .padding(horizontal = 10.dp, vertical = 4.dp),
        color = color,
        style = MaterialTheme.typography.labelMedium,
    )
}

/** Un dato con su etiqueta encima. */
@Composable
fun Stat(label: String, value: String, modifier: Modifier = Modifier) {
    Column(modifier) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MidNumberStyle, color = MaterialTheme.colorScheme.onSurface)
    }
}

/** Fila de datos; cada `Stat` dentro lleva `Modifier.weight(1f)` para repartirse a partes iguales. */
@Composable
fun StatRow(content: @Composable RowScope.() -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.Top) {
        content()
    }
}

/** Línea de la velocidad en el tiempo. */
@Composable
fun Sparkline(values: List<Float>, color: Color, modifier: Modifier = Modifier) {
    Canvas(modifier) {
        if (values.size < 2) return@Canvas
        val top = (values.maxOrNull() ?: 1f).coerceAtLeast(1f)
        val stepX = size.width / (values.size - 1)
        val path = Path()
        values.forEachIndexed { i, v ->
            val x = i * stepX
            val y = size.height - (v / top) * size.height * 0.9f - size.height * 0.05f
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        drawPath(path, color, style = Stroke(width = 4f, cap = StrokeCap.Round, join = StrokeJoin.Round))
    }
}

/** Barra de temperatura de la batería (20–50 °C): verde, ámbar o roja según lo cerca que esté del límite. */
@Composable
fun TempBar(tempC: Double?, modifier: Modifier = Modifier) {
    val t = tempC ?: 20.0
    val fraction = ((t - 20.0) / 30.0).coerceIn(0.0, 1.0).toFloat()
    val color = when {
        tempC == null -> MaterialTheme.colorScheme.outline
        t < 37.0 -> MaterialTheme.colorScheme.secondary
        t < 40.0 -> warningColor()
        else -> MaterialTheme.colorScheme.error
    }
    LinearProgressIndicator(
        progress = { fraction },
        modifier = modifier.fillMaxWidth(),
        color = color,
        trackColor = MaterialTheme.colorScheme.surfaceVariant,
    )
}


/** Código QR de `text` (negro sobre blanco, con margen para que lo lean bien los escáneres). */
@Composable
fun QrCode(text: String, contentDescription: String, modifier: Modifier = Modifier) {
    val matrix = remember(text) {
        runCatching {
            QRCodeWriter().encode(
                text,
                BarcodeFormat.QR_CODE,
                0,
                0,
                mapOf(EncodeHintType.MARGIN to 0, EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M),
            )
        }.getOrNull()
    }
    Box(
        modifier
            .background(androidx.compose.ui.graphics.Color.White, androidx.compose.foundation.shape.RoundedCornerShape(12.dp))
            .padding(16.dp)
            .semantics { this.contentDescription = contentDescription },
    ) {
        if (matrix != null) {
            Canvas(Modifier.fillMaxWidth().aspectRatio(1f)) {
                val cell = size.width / matrix.width
                for (y in 0 until matrix.height) {
                    for (x in 0 until matrix.width) {
                        if (matrix.get(x, y)) {
                            drawRect(
                                color = androidx.compose.ui.graphics.Color.Black,
                                topLeft = androidx.compose.ui.geometry.Offset(x * cell, y * cell),
                                size = androidx.compose.ui.geometry.Size(cell + 0.5f, cell + 0.5f),
                            )
                        }
                    }
                }
            }
        }
    }
}
