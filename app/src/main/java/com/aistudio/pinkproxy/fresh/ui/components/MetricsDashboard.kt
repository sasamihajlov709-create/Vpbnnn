package com.aistudio.pinkproxy.fresh.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink
import com.aistudio.pinkproxy.fresh.ui.theme.PureBlack

@Composable
fun MetricItem(label: String, value: String, color: Color) {
    Column {
        Text(label, fontSize = 9.sp, fontWeight = FontWeight.Bold, color = GentleLightPink.copy(alpha = 0.4f), letterSpacing = 1.sp)
        Text(value, fontSize = 14.sp, fontWeight = FontWeight.ExtraBold, color = color)
    }
}

@Composable
fun MetricsCard(
    speedText: String,
    bytesTransferred: String,
    sessionTime: String,
    connectivityScore: Int,
    successRate: Int,
    stabilityScore: Int,
    signalQuality: Int,
    mtu: Int,
    isPanicMode: Boolean,
    censorshipIntensity: Int
) {
    Column(modifier = Modifier.padding(16.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            MetricItem("CURRENT SPEED", speedText, GentleLightPink)
            MetricItem("STABILITY", "$stabilityScore%", if (stabilityScore > 80) Color(0xFF81C784) else Color(0xFFFFB74D))
        }
        Spacer(modifier = Modifier.height(16.dp))
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            MetricItem("TRANSFERRED", bytesTransferred, GentleMediumPink)
            MetricItem("SUCCESS RATE", "$successRate%", if (successRate > 90) Color(0xFF81C784) else Color(0xFFE57373))
        }
        Spacer(modifier = Modifier.height(16.dp))
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            MetricItem("SESSION TIME", sessionTime, Color(0xFF4FC3F7))
            MetricItem("NETWORK INTENSITY", "$censorshipIntensity%", if (censorshipIntensity < 30) Color(0xFF81C784) else Color(0xFFE57373))
        }
    }
}

@Composable
fun SpeedGraph(history: List<Long>, modifier: Modifier) {
    Canvas(modifier = modifier) {
        if (history.size < 2) return@Canvas
        val max = history.maxOrNull()?.coerceAtLeast(1024L) ?: 1024L
        val path = Path()
        val width = size.width
        val height = size.height
        val step = width / (history.size - 1)
        
        history.forEachIndexed { i, speed ->
            val x = i * step
            val y = height - (speed.toFloat() / max * height)
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        
        drawPath(
            path = path,
            color = GentleMediumPink.copy(alpha = 0.5f),
            style = Stroke(width = 2.dp.toPx())
        )
    }
}

@Composable
fun CompactActionButton(text: String, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        color = Color.White.copy(alpha = 0.05f),
        shape = RoundedCornerShape(12.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, Color.White.copy(alpha = 0.1f)),
        modifier = modifier.height(36.dp)
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(text, color = GentleLightPink, fontSize = 10.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
        }
    }
}

@Composable
fun ExpandableSection(
    title: String,
    subtitle: String? = null,
    icon: ImageVector,
    isExpanded: Boolean,
    onToggle: () -> Unit,
    content: @Composable () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(Color.White.copy(alpha = 0.02f))
            .clickable { onToggle() }
            .padding(12.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = GentleMediumPink, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(title, color = GentleLightPink, fontSize = 12.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
                if (subtitle != null) {
                    Text(subtitle, color = GentleLightPink.copy(alpha = 0.4f), fontSize = 10.sp)
                }
            }
            Icon(
                imageVector = if (isExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                contentDescription = null,
                tint = GentleMediumPink.copy(alpha = 0.5f)
            )
        }
        AnimatedVisibility(
            visible = isExpanded,
            enter = expandVertically(),
            exit = shrinkVertically()
        ) {
            content()
        }
    }
}
