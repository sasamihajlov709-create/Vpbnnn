package com.aistudio.pinkproxy.fresh.ui

import android.content.Intent
import android.util.Log
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aistudio.pinkproxy.fresh.*
import com.aistudio.pinkproxy.fresh.R
import com.aistudio.pinkproxy.fresh.ui.components.*
import com.aistudio.pinkproxy.fresh.ui.*
import com.aistudio.pinkproxy.fresh.ui.theme.GentleDarkPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink
import com.aistudio.pinkproxy.fresh.ui.theme.PureBlack
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun PinkProxyApp(
    vpnState: VpnLifecycleState,
    vpnError: String?,
    onToggle: () -> Unit,
    onRestart: () -> Unit,
    onDismissError: () -> Unit
) {
    val isActive = vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING
    var selectedTab by remember { mutableIntStateOf(0) }
    val context = LocalContext.current

    Scaffold(
        bottomBar = {
            NavigationBar(
                containerColor = Color.Black.copy(alpha = 0.8f),
                tonalElevation = 0.dp
            ) {
                val navItemColors = NavigationBarItemDefaults.colors(
                    selectedIconColor = GentleLightPink,
                    selectedTextColor = GentleLightPink,
                    unselectedIconColor = GentleLightPink.copy(alpha = 0.4f),
                    unselectedTextColor = GentleLightPink.copy(alpha = 0.4f),
                    indicatorColor = GentleMediumPink.copy(alpha = 0.2f)
                )
                
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = { Icon(Icons.Default.Dashboard, "DASHBOARD") },
                    label = { Text("DASHBOARD", fontSize = 10.sp, fontWeight = FontWeight.Bold) },
                    colors = navItemColors
                )
                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    icon = { Icon(Icons.Default.Security, "BYPASS") },
                    label = { Text("BYPASS", fontSize = 10.sp, fontWeight = FontWeight.Bold) },
                    colors = navItemColors
                )
                NavigationBarItem(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    icon = { Icon(Icons.Default.Settings, "SETTINGS") },
                    label = { Text("SETTINGS", fontSize = 10.sp, fontWeight = FontWeight.Bold) },
                    colors = navItemColors
                )
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .background(PureBlack)
        ) {
            androidx.compose.animation.Crossfade(targetState = selectedTab, label = "tab_fade") { tab ->
                when (tab) {
                    0 -> DashboardTab(
                        vpnState = vpnState,
                        vpnError = vpnError,
                        onToggle = onToggle,
                        onDismissError = onDismissError
                    )
                    1 -> BypassTab(onRestart = onRestart)
                    2 -> SettingsScreen(
                        context = context,
                        isVpnActive = isActive,
                        onSettingsChanged = onRestart
                    )
                }
            }
        }
    }
}

@Composable
fun DashboardTab(
    vpnState: VpnLifecycleState,
    vpnError: String?,
    onToggle: () -> Unit,
    onDismissError: () -> Unit
) {
    val isActive = vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING
    val bgColor1 = Color(0xFF000000)
    val bgColor2 = Color(0xFF070305)
    val bgColor3 = Color(0xFF000000)
    
    val infiniteTransition = rememberInfiniteTransition(label = "bg_anim")
    val offsetX by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1000f,
        animationSpec = infiniteRepeatable(
            animation = tween(15000, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ), label = "offset"
    )

    val bytesTransferred by ProxyStats.bytesTransferred.collectAsStateWithLifecycle(initialValue = 0L)
    val speedBytes by ProxyStats.speedBytesPerSecond.collectAsStateWithLifecycle(initialValue = 0L)
    val speedHistory by ProxyStats.speedHistory.collectAsStateWithLifecycle(initialValue = emptyList<Long>())
    val isProxyHealthy by ServiceChecker.proxyHealth.collectAsStateWithLifecycle(initialValue = true)
    val isInternetUp by ServiceChecker.internetAvailable.collectAsStateWithLifecycle(initialValue = true)
    val isProbing by ServiceChecker.isProbingState.collectAsStateWithLifecycle(initialValue = false)
    
    val activeStrategy by BypassConfig.strategy.collectAsStateWithLifecycle(initialValue = BypassStrategy.SNI_SPLIT)
    val testingStrategies by BypassConfig.testingStrategies.collectAsStateWithLifecycle(initialValue = listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.FAKE_PACKET, BypassStrategy.TCP_OOB_DESYNC))
    val signalQuality by ProxyStats.signalQuality.collectAsStateWithLifecycle(initialValue = 100)
    val isPanicMode by BypassConfig.isPanicModeFlow.collectAsStateWithLifecycle(initialValue = false)
    val stabilityScore by ProxyStats.stabilityScore.collectAsStateWithLifecycle(initialValue = 100)
    val currentMtu by BypassConfig.currentMtu.collectAsStateWithLifecycle(initialValue = 1400)
    val successRate by ProxyStats.successRate.collectAsStateWithLifecycle(initialValue = 100)
    val censorshipIntensity by ProxyStats.censorshipIntensity.collectAsStateWithLifecycle(initialValue = 0)
    val tcpCensorshipIntensity by ProxyStats.tcpCensorshipIntensity.collectAsStateWithLifecycle(initialValue = 0)
    val udpCensorshipIntensity by ProxyStats.udpCensorshipIntensity.collectAsStateWithLifecycle(initialValue = 0)
    val dnsCensorshipIntensity by ProxyStats.dnsCensorshipIntensity.collectAsStateWithLifecycle(initialValue = 0)

    var sessionTime by remember { mutableStateOf(0L) }
    LaunchedEffect(isActive) {
        if (isActive) {
            while (isActive) {
                delay(1000)
                sessionTime++
            }
        } else {
            sessionTime = 0L
        }
    }
    
    val speedKb = (speedBytes / 1024.0)
    val speedText = if (speedKb > 1024) String.format(java.util.Locale.US, "%.1f MB/s", speedKb / 1024.0) else String.format(java.util.Locale.US, "%.0f KB/s", speedKb)
    
    val hours = sessionTime / 3600
    val minutes = (sessionTime % 3600) / 60
    val seconds = sessionTime % 60
    val formattedSessionTime = if (hours > 0) {
        String.format(java.util.Locale.US, "%02d:%02d:%02d", hours, minutes, seconds)
    } else {
        String.format(java.util.Locale.US, "%02d:%02d", minutes, seconds)
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .drawBehind {
                val brush = Brush.linearGradient(
                    colors = listOf(bgColor1, bgColor2, bgColor3, bgColor2),
                    start = Offset(offsetX, offsetX / 2f),
                    end = Offset(size.width - offsetX, size.height)
                )
                drawRect(brush = brush)
            }
    ) {
        val scrollState = rememberScrollState()
        Column(
            modifier = Modifier
                .fillMaxSize()
                .widthIn(max = 600.dp)
                .align(Alignment.TopCenter)
                .verticalScroll(scrollState)
                .padding(horizontal = 20.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = stringResource(R.string.app_name),
                fontSize = 28.sp,
                fontWeight = FontWeight.ExtraBold,
                color = GentleLightPink,
                letterSpacing = (-1).sp
            )
            
            Spacer(modifier = Modifier.height(24.dp))

            when (vpnState) {
                VpnLifecycleState.RUNNING -> StatusBadge(isProxyHealthy, isInternetUp, isProbing)
                VpnLifecycleState.RECOVERING -> Text("RECOVERING CONNECTION...", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFFFFB74D), letterSpacing = 2.sp)
                VpnLifecycleState.STARTING -> Text("STARTING ENGINES...", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink, letterSpacing = 2.sp)
                VpnLifecycleState.STOPPING -> Text("STOPPING SECURELY...", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = GentleDarkPink, letterSpacing = 2.sp)
                VpnLifecycleState.FAILED, VpnLifecycleState.ERROR -> Text("CRITICAL FAILURE", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFFE57373), letterSpacing = 2.sp)
                else -> Text(stringResource(R.string.status_ready), fontSize = 12.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink.copy(alpha = 0.5f), letterSpacing = 2.sp)
            }

            Spacer(modifier = Modifier.height(32.dp))

            if (vpnError != null) {
                Surface(
                    color = Color(0xFFE57373).copy(alpha = 0.15f),
                    shape = RoundedCornerShape(16.dp),
                    border = BorderStroke(1.dp, Color(0xFFE57373).copy(alpha = 0.4f)),
                    modifier = Modifier.fillMaxWidth().padding(bottom = 24.dp)
                ) {
                    Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Warning, "Error", tint = Color(0xFFE57373), modifier = Modifier.size(24.dp))
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text("SYSTEM ALERT", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFFE57373), letterSpacing = 1.sp)
                            Text(vpnError, fontSize = 13.sp, color = GentleLightPink, lineHeight = 18.sp)
                        }
                        IconButton(onClick = onDismissError) { Icon(Icons.Default.Cancel, "Dismiss", tint = GentleMediumPink.copy(alpha = 0.6f)) }
                    }
                }
            }

            PowerButton(vpnState, onToggle, infiniteTransition)

            Spacer(modifier = Modifier.height(20.dp))

            StrategyDisplayWidget(
                activeStrategy = activeStrategy,
                testingStrategies = testingStrategies,
                isProbing = isProbing,
                isActive = isActive,
                onSelectStrategy = { /* Managed in Bypass Tab */ }
            )

            Spacer(modifier = Modifier.height(24.dp))

            if (isActive) {
                val connectivityScore by ServiceChecker.connectivityScore.collectAsStateWithLifecycle(initialValue = 0)
                
                Surface(
                    color = PureBlack,
                    shape = RoundedCornerShape(24.dp),
                    border = BorderStroke(1.dp, if (isPanicMode) Color(0xFFE57373).copy(alpha = 0.3f) else GentleMediumPink.copy(alpha = 0.1f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column {
                        if (speedHistory.isNotEmpty()) {
                            SpeedGraph(
                                history = speedHistory,
                                modifier = Modifier.fillMaxWidth().height(60.dp).padding(top = 16.dp, start = 16.dp, end = 16.dp)
                            )
                        }
                        
                        MetricsCard(
                            speedText = speedText,
                            bytesTransferred = ProxyStats.formatBytes(bytesTransferred),
                            sessionTime = formattedSessionTime,
                            connectivityScore = connectivityScore,
                            successRate = successRate,
                            stabilityScore = stabilityScore,
                            signalQuality = signalQuality,
                            mtu = currentMtu,
                            isPanicMode = isPanicMode,
                            tcpIntensity = tcpCensorshipIntensity,
                            udpIntensity = udpCensorshipIntensity,
                            dnsIntensity = dnsCensorshipIntensity
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun BypassTab(
    onRestart: () -> Unit
) {
    val context = LocalContext.current
    val currentStrategy by BypassConfig.strategy.collectAsStateWithLifecycle()
    val metrics by BypassConfig.strategyMetrics.collectAsStateWithLifecycle(initialValue = emptyList<StrategyMetric>())
    val isPanicMode by BypassConfig.isPanicModeFlow.collectAsStateWithLifecycle()
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
    ) {
        Text(
            text = "BYPASS ENGINE",
            fontSize = 24.sp,
            fontWeight = FontWeight.Black,
            color = GentleLightPink,
            modifier = Modifier.padding(bottom = 16.dp)
        )

        StrategyWidget(
            currentStrategy = currentStrategy,
            metrics = metrics,
            onSelect = { 
                RuntimeCoordinator.transitionGlobalStrategy(it, TransportType.TCP, "UI Bypass Tab Selection")
                BypassConfig.saveBypassSettings(context)
                onRestart()
            }
        )

        Spacer(modifier = Modifier.height(16.dp))

        if (isPanicMode) {
            PanicModeIndicator()
            Spacer(modifier = Modifier.height(16.dp))
        }

        // Quick Stats for Bypass
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = Color.Black.copy(alpha = 0.3f)),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text("ENGINE DIAGNOSTICS", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink)
                Spacer(modifier = Modifier.height(8.dp))
                
                val currentProfile by NetworkProfileManager.currentProfile.collectAsStateWithLifecycle()
                MetricRow(label = "Network Profile", value = currentProfile.displayName, color = Color(0xFF81C784))

                val currentDpi by ProxyStats.currentDpiType.collectAsStateWithLifecycle()
                MetricRow(label = "Detected Block Type", value = currentDpi.name, color = if (currentDpi != DpiType.NONE) Color(0xFFE57373) else GentleLightPink)
                
                val stability by ProxyStats.stabilityScore.collectAsStateWithLifecycle()
                MetricRow(label = "Path Stability", value = "$stability%", color = if (stability < 50) Color(0xFFE57373) else GentleLightPink)
            }
        }

        Spacer(modifier = Modifier.height(24.dp))
        
        Button(
            onClick = { 
                BypassConfig.resetScores()
                onRestart()
            },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = GentleDarkPink)
        ) {
            Text("FORCE RE-OPTIMIZE ENGINE", fontWeight = FontWeight.Bold)
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Strategy Config Summary
        ExpandableSection(
            title = "CURRENT PARAMETERS",
            icon = Icons.Default.Settings,
            isExpanded = true,
            onToggle = {}
        ) {
            Column(modifier = Modifier.padding(top = 8.dp)) {
                val currentFragSize by BypassConfig.currentFragSizeState.collectAsStateWithLifecycle(initialValue = 1)
                Text(
                    text = "FRAG: $currentFragSize | DELAY: ${BypassConfig.delay1}ms | TTL: ${BypassConfig.fakeTtl}",
                    fontSize = 11.sp,
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                    color = Color(0xFF81C784)
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("LIVE TRAFFIC FLOWS", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)
            val activeFlows by ProxyStats.activeFlows.collectAsStateWithLifecycle()
            Text("${activeFlows.size} ACTIVE", fontSize = 10.sp, color = GentleMediumPink)
        }

        Spacer(modifier = Modifier.height(8.dp))

        val activeFlows by ProxyStats.activeFlows.collectAsStateWithLifecycle()
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color.Black.copy(alpha = 0.2f), RoundedCornerShape(12.dp))
                .border(1.dp, GentleMediumPink.copy(alpha = 0.1f), RoundedCornerShape(12.dp))
                .padding(8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            if (activeFlows.isEmpty()) {
                Box(modifier = Modifier.fillMaxWidth().height(100.dp), contentAlignment = Alignment.Center) {
                    Text("No active data flows", color = GentleLightPink.copy(alpha = 0.3f), fontSize = 12.sp)
                }
            } else {
                activeFlows.take(15).forEach { flow ->
                    FlowItem(flow)
                }
            }
        }
    }
}

@Composable
fun FlowItem(flow: ActiveFlow) {
    Surface(
        color = Color.White.copy(alpha = 0.03f),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .background(
                        if (flow.status == "OPEN" || flow.status == "ACTIVE") Color(0xFF81C784) else Color(0xFFE57373),
                        CircleShape
                    )
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(flow.host, fontSize = 11.sp, fontWeight = FontWeight.Bold, color = GentleLightPink, maxLines = 1)
                Text("${flow.type} | ${flow.strategy.name}", fontSize = 9.sp, color = GentleLightPink.copy(alpha = 0.4f))
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(ProxyStats.formatBytes(flow.bytesSent + flow.bytesReceived), fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink)
                Text(flow.status, fontSize = 8.sp, color = GentleLightPink.copy(alpha = 0.3f))
            }
        }
    }
}

@Composable
fun PanicModeIndicator() {
    Surface(
        color = Color(0xFFE57373).copy(alpha = 0.1f),
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, Color(0xFFE57373).copy(alpha = 0.4f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Default.Error, null, tint = Color(0xFFE57373), modifier = Modifier.size(20.dp))
            Spacer(modifier = Modifier.width(12.dp))
            Column {
                Text("PANIC MODE ACTIVE", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFFE57373))
                Text("Maximum DPI evasion engaged. Stability prioritized over speed.", fontSize = 9.sp, color = Color(0xFFE57373).copy(alpha = 0.8f))
            }
        }
    }
}

@Composable
fun StrategyWidget(
    currentStrategy: BypassStrategy,
    metrics: List<StrategyMetric>,
    onSelect: (BypassStrategy) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.Black.copy(alpha = 0.4f)),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, GentleMediumPink.copy(alpha = 0.2f))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded },
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text("ACTIVE ENGINE STRATEGY", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink)
                    Text(currentStrategy.name.replace("_", " "), fontSize = 18.sp, fontWeight = FontWeight.Black, color = GentleLightPink)
                }
                Icon(
                    imageVector = if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    contentDescription = null,
                    tint = GentleLightPink.copy(alpha = 0.5f)
                )
            }
            
            if (expanded) {
                Spacer(modifier = Modifier.height(12.dp))
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    metrics.take(8).forEach { metric ->
                        val isSelected = metric.strategy == currentStrategy
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(if (isSelected) GentleDarkPink.copy(alpha = 0.2f) else Color.Transparent, RoundedCornerShape(8.dp))
                                .clickable { 
                                    onSelect(metric.strategy)
                                    expanded = false
                                }
                                .padding(8.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text(metric.strategy.name.replace("_", " "), fontSize = 12.sp, fontWeight = FontWeight.Bold, color = if (isSelected) GentleLightPink else GentleLightPink.copy(alpha = 0.7f))
                                Text("Score: ${metric.score} | SR: ${if (metric.successes + metric.failures > 0) (metric.successes * 100 / (metric.successes + metric.failures)) else 0}%", fontSize = 9.sp, color = GentleLightPink.copy(alpha = 0.4f))
                            }
                            if (isSelected) {
                                Icon(Icons.Default.CheckCircle, null, tint = Color(0xFF81C784), modifier = Modifier.size(16.dp))
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun MetricRow(label: String, value: String, color: Color) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, fontSize = 11.sp, color = GentleLightPink.copy(alpha = 0.6f))
        Text(value, fontSize = 11.sp, color = color, fontWeight = FontWeight.Bold)
    }
}
