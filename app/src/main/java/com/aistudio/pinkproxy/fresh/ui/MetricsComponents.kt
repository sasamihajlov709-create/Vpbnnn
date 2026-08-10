package com.aistudio.pinkproxy.fresh.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import com.aistudio.pinkproxy.fresh.R
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aistudio.pinkproxy.fresh.BypassStrategy
import com.aistudio.pinkproxy.fresh.VpnLifecycleState
import com.aistudio.pinkproxy.fresh.DpiEngine
import com.aistudio.pinkproxy.fresh.DpiAnalyzer
import com.aistudio.pinkproxy.fresh.ProxyStats
import java.util.Locale
import com.aistudio.pinkproxy.fresh.ui.theme.GentleDarkPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink
import com.aistudio.pinkproxy.fresh.ui.theme.PureBlack

@Composable
fun StatusBadge(isHealthy: Boolean, isInternet: Boolean, isProbing: Boolean) {
    val color = when {
        !isInternet -> Color(0xFF9E9E9E)
        isProbing -> GentleMediumPink
        isHealthy -> Color(0xFF81C784)
        else -> Color(0xFFE57373)
    }
    
    val text = when {
        !isInternet -> stringResource(R.string.status_no_internet)
        isProbing -> stringResource(R.string.status_probing)
        !isHealthy -> stringResource(R.string.status_recovering)
        else -> stringResource(R.string.status_protected)
    }

    Surface(
        color = color.copy(alpha = 0.15f),
        shape = RoundedCornerShape(20.dp),
        border = BorderStroke(1.dp, color.copy(alpha = 0.3f))
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(modifier = Modifier.size(6.dp).background(color, CircleShape))
            Spacer(modifier = Modifier.width(8.dp))
            Text(text = text, fontSize = 10.sp, fontWeight = FontWeight.Black, color = color, letterSpacing = 1.sp)
        }
    }
}

@Composable
fun PowerButton(state: VpnLifecycleState, onToggle: () -> Unit, transition: InfiniteTransition) {
    val isActive = state == VpnLifecycleState.RUNNING || state == VpnLifecycleState.RECOVERING
    val isProcessing = state == VpnLifecycleState.STARTING || state == VpnLifecycleState.STOPPING || state == VpnLifecycleState.RECOVERING
    val isError = state == VpnLifecycleState.FAILED || state == VpnLifecycleState.ERROR

    val pulseScale by transition.animateFloat(
        initialValue = 1f,
        targetValue = if (isActive) 1.15f else if (isProcessing) 1.05f else 1f,
        animationSpec = infiniteRepeatable(tween(if (isProcessing) 800 else 1500), RepeatMode.Reverse), label = "pulse"
    )

    val buttonColor by animateColorAsState(
        targetValue = when {
            isError -> Color(0xFFE57373)
            isActive -> GentleDarkPink
            isProcessing -> GentleMediumPink.copy(alpha = 0.8f)
            else -> Color.Black
        },
        animationSpec = tween(500), label = "color"
    )

    val iconTint by animateColorAsState(
        targetValue = if (isActive || isError || isProcessing) Color.White else GentleDarkPink,
        animationSpec = tween(500), label = "tint"
    )
    
    Box(contentAlignment = Alignment.Center, modifier = Modifier.size(180.dp)) {
        if (isActive || isProcessing || isError) {
            Box(
                modifier = Modifier
                    .size(160.dp)
                    .background(buttonColor.copy(alpha = 0.2f), CircleShape)
            )
        }
        
        Surface(
            onClick = onToggle,
            shape = CircleShape,
            color = buttonColor,
            border = BorderStroke(2.dp, if (isActive) GentleLightPink else GentleMediumPink.copy(alpha = 0.5f)),
            modifier = Modifier.size(130.dp)
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = androidx.compose.material.icons.Icons.Default.PowerSettingsNew,
                    contentDescription = "Power Toggle",
                    tint = iconTint,
                    modifier = Modifier.size(48.dp)
                )
            }
        }
    }
}

@Composable
fun SpeedGraph(history: List<Long>, modifier: Modifier = Modifier) {
    val maxSpeed = (history.maxOrNull() ?: 1L).coerceAtLeast(1024L)
    Canvas(modifier = modifier) {
        if (history.isEmpty()) return@Canvas
        val width = size.width
        val height = size.height
        val step = width / 60f
        
        val path = Path()
        history.take(60).forEachIndexed { i, speed ->
            val x = width - (i * step)
            val y = (height - (speed.toFloat() / maxSpeed * height)).coerceIn(0f, height)
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        
        drawPath(
            path = path,
            color = GentleMediumPink,
            style = Stroke(
                width = 2.dp.toPx(), 
                cap = StrokeCap.Round, 
                join = StrokeJoin.Round
            )
        )
        
        val fillPath = Path().apply {
            addPath(path)
            lineTo(width - (history.take(60).size - 1) * step, height)
            lineTo(width, height)
            close()
        }
        drawPath(
            path = fillPath,
            brush = Brush.verticalGradient(
                colors = listOf(GentleMediumPink.copy(alpha = 0.3f), Color.Transparent),
                startY = 0f,
                endY = height
            )
        )
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
    Column(modifier = Modifier.padding(20.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            MetricItem(stringResource(R.string.label_speed), speedText, GentleLightPink)
            MetricItem(stringResource(R.string.label_data), bytesTransferred, GentleMediumPink)
            MetricItem(stringResource(R.string.label_mtu), mtu.toString(), GentleMediumPink)
            MetricItem(stringResource(R.string.label_time), sessionTime, GentleMediumPink)
        }
        Spacer(modifier = Modifier.height(20.dp))
        HorizontalDivider(color = GentleMediumPink.copy(alpha = 0.1f))
        Spacer(modifier = Modifier.height(20.dp))
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            MetricItem(stringResource(R.string.label_health), "$connectivityScore%", if (connectivityScore > 70) Color(0xFF81C784) else Color(0xFFFFB74D))
            MetricItem(stringResource(R.string.label_stability), "$stabilityScore%", if (stabilityScore > 80) Color(0xFF81C784) else if (stabilityScore > 50) Color(0xFFFFB74D) else Color(0xFFE57373))
            MetricItem(stringResource(R.string.label_censorship), "$censorshipIntensity%", if (censorshipIntensity < 30) Color(0xFF81C784) else Color(0xFFE57373))
            MetricItem(stringResource(R.string.label_quality), "$signalQuality%", if (signalQuality > 70) Color(0xFF81C784) else Color(0xFFE57373))
        }
    }
}

@Composable
fun MetricItem(label: String, value: String, color: Color) {
    Column {
        Text(label, fontSize = 9.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink.copy(alpha = 0.4f))
        Text(value, fontSize = 15.sp, fontWeight = FontWeight.ExtraBold, color = color)
    }
}

@Composable
fun MetricSmallDetail(label: String, value: String, color: Color) {
    Column {
        Text(label, fontSize = 8.sp, fontWeight = FontWeight.Bold, color = GentleLightPink.copy(alpha = 0.4f))
        Text(value, fontSize = 10.sp, fontWeight = FontWeight.ExtraBold, color = color)
    }
}

@Composable
fun ExpandableSection(
    title: String,
    subtitle: String = "",
    icon: androidx.compose.ui.graphics.vector.ImageVector? = null,
    isExpanded: Boolean,
    onToggle: () -> Unit,
    content: @Composable () -> Unit = {}
) {
    Column {
        Surface(
            onClick = onToggle,
            color = Color.Transparent,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.padding(vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (icon != null) {
                        Icon(
                            imageVector = icon,
                            contentDescription = null,
                            tint = GentleMediumPink,
                            modifier = Modifier.size(18.dp).padding(end = 8.dp)
                        )
                    }
                    Column {
                        Text(title, fontSize = 11.sp, fontWeight = FontWeight.Black, color = GentleLightPink, letterSpacing = 1.sp)
                        if (subtitle.isNotEmpty()) {
                            Text(subtitle, fontSize = 10.sp, color = GentleMediumPink.copy(alpha = 0.6f))
                        }
                    }
                }
                Icon(
                    imageVector = if (isExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    contentDescription = null,
                    tint = GentleMediumPink.copy(alpha = 0.4f),
                    modifier = Modifier.size(16.dp)
                )
            }
        }
        if (isExpanded) {
            content()
        }
    }
}

@Composable
fun CompactActionButton(text: String, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        color = GentleMediumPink.copy(alpha = 0.1f),
        shape = RoundedCornerShape(12.dp),
        modifier = modifier
    ) {
        Box(contentAlignment = Alignment.Center, modifier = Modifier.padding(vertical = 12.dp)) {
            Text(text, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)
        }
    }
}

@Composable
fun DiagnosticsContent(p8: Int, p16: Int, conns: Int, rtt: Long, win: Int, ds: Long, df: Long) {
    val clipboardManager = androidx.compose.ui.platform.LocalClipboardManager.current
    val report = """
        SYSTEM DIAGNOSTICS REPORT
        Memory Pool 8K: $p8
        Memory Pool 16K: $p16
        Active Connections: $conns
        Latency (RTT): ${rtt}ms
        TCP Window: $win
        DNS Success: $ds
        DNS Errors: $df
    """.trimIndent()

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp, bottom = 16.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(GentleMediumPink.copy(alpha = 0.05f))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        DiagRow("MEMORY POOL", "8K: $p8 | 16K: $p16")
        DiagRow("CONNECTIONS", "$conns ACTIVE")
        DiagRow("LATENCY (RTT)", "${rtt}ms")
        DiagRow("WINDOW", "$win PACKETS")
        DiagRow("DNS STATUS", "OK: $ds | ERR: $df")
        
        Spacer(modifier = Modifier.height(4.dp))
        
        Button(
            onClick = { clipboardManager.setText(androidx.compose.ui.text.AnnotatedString(report)) },
            modifier = Modifier.fillMaxWidth().height(32.dp),
            contentPadding = PaddingValues(0.dp),
            colors = ButtonDefaults.buttonColors(containerColor = GentleMediumPink.copy(alpha = 0.2f)),
            shape = RoundedCornerShape(8.dp)
        ) {
            Text("COPY SYSTEM REPORT", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)
        }
    }
}

@Composable
fun DiagRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, fontSize = 10.sp, color = GentleMediumPink.copy(alpha = 0.5f))
        Text(value, fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color.White)
    }
}

@Composable
fun StrategyConfigContent(strategy: BypassStrategy, onMenu: () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp, bottom = 16.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(PureBlack)
            .border(1.dp, GentleMediumPink.copy(alpha = 0.1f), RoundedCornerShape(16.dp))
            .clickable { onMenu() }
            .padding(16.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text("CURRENT METHOD", fontSize = 9.sp, color = GentleMediumPink.copy(alpha = 0.5f))
                Text(strategy.name.replace("_", " "), fontSize = 14.sp, fontWeight = FontWeight.Bold, color = Color.White)
            }
            Icon(Icons.Default.Settings, null, tint = GentleMediumPink, modifier = Modifier.size(18.dp))
        }
    }
}

@Composable
fun LogsContent(recovery: List<String>, traffic: List<String>) {
    val clipboardManager = androidx.compose.ui.platform.LocalClipboardManager.current
    val allLogs = (recovery + traffic)
    
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp)
            .heightIn(min = 120.dp, max = 250.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(PureBlack)
            .border(1.dp, GentleMediumPink.copy(alpha = 0.15f), RoundedCornerShape(16.dp))
            .padding(12.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("ENGINE REAL-TIME LOGS", fontSize = 10.sp, fontWeight = FontWeight.Black, color = GentleMediumPink, letterSpacing = 1.sp)
            Surface(
                onClick = { clipboardManager.setText(androidx.compose.ui.text.AnnotatedString(allLogs.joinToString("\n"))) },
                color = GentleMediumPink.copy(alpha = 0.1f),
                shape = RoundedCornerShape(4.dp)
            ) {
                Text("COPY ALL", fontSize = 8.sp, fontWeight = FontWeight.Bold, color = GentleLightPink, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
            }
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .verticalScroll(rememberScrollState())
        ) {
            allLogs.takeLast(40).reversed().forEach { log ->
                val color = when {
                    log.contains("Healing") || log.contains("Success") -> Color(0xFF81C784)
                    log.contains("Error") || log.contains("Fail") || log.contains("Warning") -> Color(0xFFE57373)
                    log.contains("System") || log.contains("Recovery") -> GentleMediumPink
                    else -> Color.White.copy(alpha = 0.5f)
                }
                Text(
                    text = log,
                    fontSize = 9.sp,
                    fontFamily = FontFamily.Monospace,
                    color = color,
                    modifier = Modifier.padding(vertical = 1.dp),
                    lineHeight = 12.sp
                )
            }
        }
    }
}


@Composable
fun CensorshipFingerprintCard(fingerprint: DpiAnalyzer.CensorshipFingerprint) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.Black.copy(alpha = 0.4f)),
        shape = RoundedCornerShape(24.dp),
        border = BorderStroke(1.dp, GentleMediumPink.copy(alpha = 0.2f))
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Text(
                "CENSORSHIP FINGERPRINT",
                fontSize = 11.sp,
                fontWeight = FontWeight.Black,
                color = GentleMediumPink,
                letterSpacing = 1.5.sp
            )
            Spacer(modifier = Modifier.height(16.dp))
            
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                FingerprintItem("TCP RESET", "${(fingerprint.rstRate * 100).toInt()}%", Color(0xFFE57373))
                FingerprintItem("SNI BLOCK", "${(fingerprint.sniBlockRate * 100).toInt()}%", Color(0xFFF06292))
                FingerprintItem("STALLS", "${(fingerprint.stallRate * 100).toInt()}%", Color(0xFFFFB74D))
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                FingerprintItem("TIMEOUTS", "${(fingerprint.timeoutRate * 100).toInt()}%", Color(0xFF9575CD))
                FingerprintItem("JITTER", "${fingerprint.jitter.toInt()}ms", Color(0xFF4FC3F7))
                FingerprintItem("INTENSITY", "${fingerprint.intensity}%", GentleDarkPink)
            }
        }
    }
}

@Composable
fun FingerprintItem(label: String, value: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(label, fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color.White.copy(alpha = 0.5f))
        Text(value, fontSize = 16.sp, fontWeight = FontWeight.Black, color = color)
    }
}

@Composable
fun ActiveFlowsContent(flows: List<com.aistudio.pinkproxy.fresh.ActiveFlow>) {
    LazyColumn(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp, bottom = 16.dp)
            .heightIn(max = 300.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(PureBlack)
            .border(1.dp, GentleMediumPink.copy(alpha = 0.1f), RoundedCornerShape(16.dp))
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        if (flows.isEmpty()) {
            item {
                Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                    Text(
                        "NO ACTIVE SESSIONS",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp,
                        color = GentleMediumPink.copy(alpha = 0.3f)
                    )
                }
            }
        } else {
            items(flows, key = { it.id }) { flow ->
                FlowRow(flow)
                HorizontalDivider(color = GentleMediumPink.copy(alpha = 0.05f))
            }
        }
    }
}

@Composable
fun FlowRow(flow: com.aistudio.pinkproxy.fresh.ActiveFlow) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(flow.host, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color.White, maxLines = 1)
            Text(
                "${flow.type} • ${flow.strategy.name.replace("_", " ")}",
                fontSize = 9.sp,
                color = GentleMediumPink.copy(alpha = 0.5f)
            )
            if (flow.reasoning.isNotEmpty()) {
                Text(
                    flow.reasoning,
                    fontSize = 8.5.sp,
                    color = GentleLightPink.copy(alpha = 0.7f),
                    maxLines = 1
                )
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            MetricSmallDetail("UP", formatFlowSize(flow.bytesSent), GentleLightPink)
            MetricSmallDetail("DOWN", formatFlowSize(flow.bytesReceived), GentleMediumPink)
        }
    }
}

private fun formatFlowSize(bytes: Long): String {
    return when {
        bytes >= 1024 * 1024 -> "%.1fM".format(bytes / (1024f * 1024f))
        bytes >= 1024 -> "${bytes / 1024}K"
        else -> "${bytes}B"
    }
}
