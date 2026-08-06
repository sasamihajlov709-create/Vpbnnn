package com.aistudio.pinkproxy.fresh

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.Fill
import androidx.compose.foundation.Canvas
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.SimpleDateFormat
import java.util.*
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.ui.viewinterop.AndroidView
import com.aistudio.pinkproxy.fresh.ui.*
import com.aistudio.pinkproxy.fresh.ui.theme.MyApplicationTheme
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleDarkPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleDeepPink
import com.aistudio.pinkproxy.fresh.ui.theme.PureBlack
import com.aistudio.pinkproxy.fresh.ui.theme.DarkGreyBlack
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.SettingsApplications
import androidx.compose.material.icons.filled.FilterList

class MainActivity : ComponentActivity() {
    private fun formatBytes(bytes: Long) = ProxyStats.formatBytes(bytes)
    private val vpnLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK || android.net.VpnService.prepare(this) == null) {
            startVpnService()
        } else {
            android.widget.Toast.makeText(this, "VPN permission is required to run", android.widget.Toast.LENGTH_LONG).show()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted ->
        if (isGranted) {
            Log.d("MainActivity", "Notification permission granted")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        enableEdgeToEdge()
        
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            if (androidx.core.content.ContextCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                notificationPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        
        try {
            PinkVpnService.loadFilterSettings(this)
            BypassConfig.loadTuningSettings(this)
            RobustResolver.loadDnsSettings(this)
        } catch (e: Throwable) {
            android.util.Log.e("MainActivity", "Error loading initial settings", e)
        }
        
        val prefs = getSharedPreferences("pink_proxy_settings", MODE_PRIVATE)
        val autoConnect = prefs.getBoolean("auto_connect_on_launch", false)
        
        setContent {
            val vpnState by VpnRuntimeState.lifecycleState.collectAsStateWithLifecycle()
            val vpnError by VpnRuntimeState.lastError.collectAsStateWithLifecycle()
            val isVpnActive = vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING
            val context = androidx.compose.ui.platform.LocalContext.current
            
            LaunchedEffect(Unit) {
                if (autoConnect && vpnState == VpnLifecycleState.IDLE) {
                    toggleVpn(false) 
                }
            }

            MyApplicationTheme(dynamicColor = false) {
                PinkProxyApp(
                    vpnState = vpnState,
                    vpnError = vpnError,
                    onToggle = { toggleVpn(isVpnActive) },
                    onRestart = { 
                        if (isVpnActive) {
                            try {
                                val intent = Intent(context, PinkVpnService::class.java).apply {
                                    action = "RESTART"
                                }
                                androidx.core.content.ContextCompat.startForegroundService(context, intent)
                            } catch (e: Throwable) {
                                android.util.Log.e("MainActivity", "Quick restart failed: ${e.message}")
                            }
                        }
                    },
                    onDismissError = { VpnRuntimeState.clearError() }
                )
            }
        }
    }

    private fun toggleVpn(isActive: Boolean) {
        if (isActive) {
            stopVpnService()
        } else {
            try {
                val vpnIntent = VpnService.prepare(this)
                if (vpnIntent != null) {
                    vpnLauncher.launch(vpnIntent)
                } else {
                    startVpnService()
                }
            } catch (e: SecurityException) {
                android.util.Log.e("MainActivity", "VPN preparation failed", e)
                android.widget.Toast.makeText(
                    this,
                    "Security Error: Please restart the app or check VPN permissions.",
                    android.widget.Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    @SuppressLint("BatteryLife")
    private fun requestIgnoreBatteryOptimizations() {
        try {
            val packageName = packageName
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
                startActivity(intent)
            }
        } catch (e: Throwable) {
            Log.e("MainActivity", "Failed to request battery optimization exemption", e)
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, PinkVpnService::class.java)
        try {
            androidx.core.content.ContextCompat.startForegroundService(this, intent)
        } catch (e: Throwable) {
            Log.e("MainActivity", "Failed to start VPN service: ${e.message}")
        }
    }

    private fun stopVpnService() {
        val intent = Intent(this, PinkVpnService::class.java).apply {
            action = "STOP"
        }
        try {
            androidx.core.content.ContextCompat.startForegroundService(this, intent)
        } catch (e: Throwable) {
            Log.e("MainActivity", "Failed to stop VPN service: ${e.message}")
        }
    }
}

@Composable
fun PinkProxyApp(
    vpnState: VpnLifecycleState,
    vpnError: String?,
    onToggle: () -> Unit,
    onRestart: () -> Unit,
    onDismissError: () -> Unit
) {
    val isActive = vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING
    val bgColor1 = Color(0xFF000000) // Pure black
    val bgColor2 = Color(0xFF070305) // Deep charcoal black with subtle dark hue
    val bgColor3 = Color(0xFF000000) // Pure black
    
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
    val activeConnections by ProxyStats.activeConnections.collectAsStateWithLifecycle(initialValue = 0)
    val speedBytes by ProxyStats.speedBytesPerSecond.collectAsStateWithLifecycle(initialValue = 0L)
    val speedHistory by ProxyStats.speedHistory.collectAsStateWithLifecycle(initialValue = emptyList<Long>())
    val errorCount by ProxyStats.errors.collectAsStateWithLifecycle(initialValue = 0L)
    val censorshipIntensity by ProxyStats.censorshipIntensity.collectAsStateWithLifecycle(initialValue = 0)
    val serviceStatuses by ServiceChecker.statuses.collectAsStateWithLifecycle(initialValue = emptyList<ServiceChecker.ServiceStatus>())
    val isProxyHealthy by ServiceChecker.proxyHealth.collectAsStateWithLifecycle(initialValue = true)
    val isInternetUp by ServiceChecker.internetAvailable.collectAsStateWithLifecycle(initialValue = true)
    val isProbing by ServiceChecker.isProbingState.collectAsStateWithLifecycle(initialValue = false)
    val lastCheckTime by ServiceChecker.lastCheckTime.collectAsStateWithLifecycle(initialValue = 0L)

    val recoveryLog by ProxyStats.recoveryLog.collectAsStateWithLifecycle(initialValue = emptyList<String>())
    val trafficLog by ProxyStats.trafficLog.collectAsStateWithLifecycle(initialValue = emptyList<String>())
    val activeStrategy by BypassConfig.strategy.collectAsStateWithLifecycle(initialValue = BypassStrategy.SNI_SPLIT)
    val testingStrategies by BypassConfig.testingStrategies.collectAsStateWithLifecycle(initialValue = listOf(BypassStrategy.SNI_SPLIT, BypassStrategy.FAKE_PACKET, BypassStrategy.TCP_OOB_DESYNC))
    val signalQuality by ProxyStats.signalQuality.collectAsStateWithLifecycle(initialValue = 100)
    val currentNetworkType by BypassConfig.currentNetworkType.collectAsStateWithLifecycle(initialValue = NetworkType.UNKNOWN)
    val currentRttMs by BypassConfig.currentRttMs.collectAsStateWithLifecycle(initialValue = 50L)
    val currentFragSize by BypassConfig.currentFragSizeState.collectAsStateWithLifecycle(initialValue = 1)
    val topHosts by ProxyStats.topHosts.collectAsStateWithLifecycle(initialValue = emptyList<Pair<String, Int>>())
    val isCharging by BypassConfig.isChargingFlow.collectAsStateWithLifecycle(initialValue = true)
    val pool8kSize by ProxyStats.pool8kSize.collectAsStateWithLifecycle(initialValue = 0)
    val pool16kSize by ProxyStats.pool16kSize.collectAsStateWithLifecycle(initialValue = 0)
    val congestionWindow by ProxyStats.congestionWindow.collectAsStateWithLifecycle(initialValue = 10)
    val dnsSuccess by ProxyStats.dnsSuccessCount.collectAsStateWithLifecycle(initialValue = 0L)
    val dnsFailure by ProxyStats.dnsFailureCount.collectAsStateWithLifecycle(initialValue = 0L)
    val activeFlows by ProxyStats.activeFlows.collectAsStateWithLifecycle(initialValue = emptyList())
    val isPanicMode by BypassConfig.isPanicModeFlow.collectAsStateWithLifecycle(initialValue = false)
    val stabilityScore by ProxyStats.stabilityScore.collectAsStateWithLifecycle(initialValue = 100)
    val currentMtu by BypassConfig.currentMtu.collectAsStateWithLifecycle(initialValue = 1400)
    val successRate by ProxyStats.successRate.collectAsStateWithLifecycle(initialValue = 100)
    
    val censorshipFingerprint by produceState(initialValue = DpiEngine.getCensorshipFingerprint()) {
        while (true) {
            delay(5000)
            value = DpiEngine.getCensorshipFingerprint()
        }
    }

    var showStrategyMenu by remember { mutableStateOf(false) }
    
    var showDiagnostics by remember { mutableStateOf(false) }
    var showActiveFlows by remember { mutableStateOf(false) }
    var showStrategyStats by remember { mutableStateOf(false) }
    var showStrategyConfig by remember { mutableStateOf(false) }
    var showLogs by remember { mutableStateOf(false) }
    
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
    
    val context = LocalContext.current
    
    // Check and request notification permission unconditionally at the root
    val launcher = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestPermission()
    ) { }
    
    androidx.compose.runtime.LaunchedEffect(Unit) {
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            val notificationPermission = "android.permission.POST_NOTIFICATIONS"
            val permissionCheck = androidx.core.content.ContextCompat.checkSelfPermission(context, notificationPermission)
            if (permissionCheck != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                launcher.launch(notificationPermission)
            }
        }
    }

    // Derived states for smoother UI
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
                .padding(WindowInsets.safeDrawing.asPaddingValues())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Minimal Header
            Text(
                text = stringResource(R.string.app_name),
                fontSize = 28.sp,
                fontWeight = FontWeight.ExtraBold,
                color = GentleLightPink,
                letterSpacing = (-1).sp
            )
            
            Spacer(modifier = Modifier.height(24.dp))

            // Main Status Indicator
            when (vpnState) {
                VpnLifecycleState.RUNNING -> StatusBadge(isProxyHealthy, isInternetUp, isProbing)
                VpnLifecycleState.RECOVERING -> Text(
                    text = "RECOVERING CONNECTION...",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFFFB74D),
                    letterSpacing = 2.sp
                )
                VpnLifecycleState.STARTING -> Text(
                    text = "STARTING ENGINES...",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = GentleMediumPink,
                    letterSpacing = 2.sp
                )
                VpnLifecycleState.STOPPING -> Text(
                    text = "STOPPING SECURELY...",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = GentleDarkPink,
                    letterSpacing = 2.sp
                )
                VpnLifecycleState.FAILED, VpnLifecycleState.ERROR -> Text(
                    text = "CRITICAL FAILURE",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFE57373),
                    letterSpacing = 2.sp
                )
                else -> Text(
                    text = stringResource(R.string.status_ready),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = GentleMediumPink.copy(alpha = 0.5f),
                    letterSpacing = 2.sp
                )
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Error Banner
            if (vpnError != null) {
                Surface(
                    color = Color(0xFFE57373).copy(alpha = 0.15f),
                    shape = RoundedCornerShape(16.dp),
                    border = BorderStroke(1.dp, Color(0xFFE57373).copy(alpha = 0.4f)),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 24.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Warning,
                            contentDescription = "Error",
                            tint = Color(0xFFE57373),
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "SYSTEM ALERT",
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFFE57373),
                                letterSpacing = 1.sp
                            )
                            Text(
                                text = vpnError,
                                fontSize = 13.sp,
                                color = GentleLightPink,
                                lineHeight = 18.sp
                            )
                        }
                        IconButton(onClick = onDismissError) {
                            Icon(
                                imageVector = Icons.Default.Cancel,
                                contentDescription = "Dismiss",
                                tint = GentleMediumPink.copy(alpha = 0.6f)
                            )
                        }
                    }
                }
            }

            // Power Button (The Heart)
            PowerButton(vpnState, onToggle, infiniteTransition)

            Spacer(modifier = Modifier.height(20.dp))

            // Strategy Display Widget (Working Strategy & Strategies Being Tested)
            StrategyDisplayWidget(
                activeStrategy = activeStrategy,
                testingStrategies = testingStrategies,
                isProbing = isProbing,
                isActive = isActive,
                onSelectStrategy = { showStrategyConfig = !showStrategyConfig }
            )

            if (isActive) {
                CensorshipFingerprintCard(censorshipFingerprint)
            }

            Spacer(modifier = Modifier.height(24.dp))

            if (isActive) {
                val connectivityScore by ServiceChecker.connectivityScore.collectAsStateWithLifecycle(initialValue = 0)
                
                // Compact Metrics Card
                val speedHistory by ProxyStats.speedHistory.collectAsStateWithLifecycle(emptyList<Long>())
                
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
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(60.dp)
                                    .padding(top = 16.dp, start = 16.dp, end = 16.dp)
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
                            censorshipIntensity = censorshipIntensity
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Action Bar
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    CompactActionButton("OPTIMIZE", Modifier.weight(1f)) { 
                        try {
                            val intent = Intent(context, PinkVpnService::class.java).apply { action = "RESTART" }
                            androidx.core.content.ContextCompat.startForegroundService(context, intent)
                        } catch (e: Throwable) {
                            Log.e("MainActivity", "Failed to restart VPN: ${e.message}")
                        }
                    }
                    CompactActionButton("STATS", Modifier.weight(1f)) { showStrategyStats = true }
                    CompactActionButton("LOGS", Modifier.weight(1f)) { showLogs = true }
                }

                Spacer(modifier = Modifier.height(24.dp))
            }
            
            // Expandable Diagnostic Sections
            if (isActive) {
                ExpandableSection(
                    title = "CORE DIAGNOSTICS",
                    icon = Icons.Default.Build,
                    isExpanded = showDiagnostics,
                    onToggle = { showDiagnostics = !showDiagnostics }
                ) {
                    Column(modifier = Modifier.padding(top = 8.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            MetricItem("BUFFER POOL", "8K: $pool8kSize/64 | 16K: $pool16kSize/32", GentleMediumPink)
                            MetricItem("ACTIVE TCP", "$activeConnections CONNS", Color(0xFF4FC3F7))
                        }
                        Spacer(modifier = Modifier.height(12.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            MetricItem("CONGESTION", "${congestionWindow} pkts/burst", Color(0xFFBA68C8))
                            MetricItem("DNS HEALTH", "OK: $dnsSuccess | ERR: $dnsFailure", if (dnsFailure > 10) Color(0xFFE57373) else Color(0xFF81C784))
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                ExpandableSection(
                    title = "ACTIVE SESSIONS",
                    subtitle = "${activeFlows.size} FLOWS",
                    icon = Icons.Default.SwapHoriz,
                    isExpanded = showActiveFlows,
                    onToggle = { showActiveFlows = !showActiveFlows }
                ) {
                    ActiveFlowsContent(activeFlows)
                }

                Spacer(modifier = Modifier.height(12.dp))
            }
            if (isActive) {
                ExpandableSection(
                    title = "STRATEGY CONFIG",
                    icon = Icons.Default.Settings,
                    isExpanded = showStrategyConfig,
                    onToggle = { showStrategyConfig = !showStrategyConfig }
                ) {
                    Column(modifier = Modifier.padding(top = 8.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            MetricItem("ACTIVE DPI EVASION", activeStrategy.name.replace("_", " "), GentleLightPink)
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "FRAG (Dyn/Base): $currentFragSize / ${BypassConfig.frag1} | DELAY: ${BypassConfig.delay1}ms | TTL: ${BypassConfig.fakeTtl}",
                            fontSize = 9.sp,
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                            color = Color(0xFF81C784)
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            MetricItem("CENSORSHIP LVL", "$censorshipIntensity%", if (censorshipIntensity < 25) Color(0xFF81C784) else Color(0xFFE57373))
                            MetricItem("STABILITY", "$stabilityScore%", if (stabilityScore > 80) Color(0xFF81C784) else Color(0xFFFFB74D))
                        }
                    }
                }
                Spacer(modifier = Modifier.height(12.dp))
            }
                        
            if (isActive) {
                ExpandableSection(
                    title = "SYSTEM LOGS",
                    icon = Icons.AutoMirrored.Filled.List,
                    isExpanded = showLogs,
                    onToggle = { showLogs = !showLogs }
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 120.dp)
                            .background(Color.Black.copy(alpha = 0.3f), RoundedCornerShape(8.dp))
                            .padding(8.dp)
                            .verticalScroll(rememberScrollState())
                    ) {
                        recoveryLog.forEach { log ->
                            Text(
                                text = log,
                                color = if (log.contains("Healing") || log.contains("Optimizing")) GentleDarkPink else GentleMediumPink.copy(alpha = 0.6f),
                                fontSize = 9.sp,
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                modifier = Modifier.padding(vertical = 1.dp)
                            )
                        }
                        
                        if (trafficLog.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                "REAL-TIME TRAFFIC",
                                color = GentleMediumPink,
                                fontSize = 8.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(bottom = 4.dp)
                            )
                            trafficLog.forEach { host ->
                                val category = HostClassifier.classify(host)
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Box(
                                        modifier = Modifier
                                            .size(4.dp)
                                            .background(
                                                when(category) {
                                                    HostCategory.AI -> Color(0xFFCE93D8)
                                                    HostCategory.STREAMING -> Color(0xFFE57373)
                                                    HostCategory.MESSENGER -> Color(0xFF81C784)
                                                    HostCategory.SOCIAL -> Color(0xFF64B5F6)
                                                    HostCategory.DEV -> Color(0xFFBA68C8)
                                                    else -> GentleMediumPink.copy(alpha = 0.5f)
                                                },
                                                CircleShape
                                            )
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = host,
                                        color = GentleLightPink.copy(alpha = 0.7f),
                                        fontSize = 9.sp,
                                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                                    )
                                }
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    CompactActionButton("EXPORT DIAGNOSTICS", Modifier.fillMaxWidth()) {
                        val report = StringBuilder().apply {
                            appendLine("=== PinkProxy Diagnostic Report ===")
                            appendLine("OS: Android ${android.os.Build.VERSION.RELEASE} (API ${android.os.Build.VERSION.SDK_INT})")
                            appendLine("Device: ${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
                            appendLine("Strategy: ${BypassConfig.strategy.value.name}")
                            appendLine("Censorship Level: ${ProxyStats.censorshipIntensity.value}%")
                            appendLine("Stability: ${ProxyStats.stabilityScore.value}%")
                            appendLine("DNS Mode: ${RobustResolver.dnsMode}")
                            appendLine("\n=== Recent Logs ===")
                            recoveryLog.takeLast(20).forEach { appendLine(it) }
                        }.toString()

                        val shareIntent = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_SUBJECT, "PinkProxy Diagnostics")
                            putExtra(Intent.EXTRA_TEXT, report)
                        }
                        try {
                            context.startActivity(Intent.createChooser(shareIntent, "Share Diagnostics"))
                        } catch (e: Throwable) {
                            android.widget.Toast.makeText(context, "Could not open share sheet", android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))
            }
                        
            // Minimalist Help/Guide (Always visible but collapsed by default)
            var showGuide by remember { mutableStateOf(false) }
            ExpandableSection(
                title = "CONNECTION GUIDE",
                icon = Icons.Default.Info,
                isExpanded = showGuide,
                onToggle = { showGuide = !showGuide }
            ) {
                Column {
                    Text(
                        text = "• Системный обход:\n" +
                               "  VPN перехватывает весь трафик через tun2socks и маршрутизирует его через DPI-bypass движок. Большинство приложений, включая официальный YouTube клиент, работают автоматически.\n\n" +
                               "• Поддержка Telegram:\n" +
                               "  Трафик Telegram автоматически перехватывается, но для большей надежности (например, для звонков) можно применить прямые настройки SOCKS5.",
                        fontSize = 11.sp,
                        color = GentleLightPink.copy(alpha = 0.6f),
                        lineHeight = 16.sp,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    CompactActionButton("Настроить Telegram Автоматически", Modifier.fillMaxWidth()) {
                        try {
                            val intent = android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse("tg://socks?server=127.0.0.1&port=18080&user=&pass="))
                            intent.flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                            context.startActivity(intent)
                        } catch (e: Throwable) {
                            android.widget.Toast.makeText(context, "Telegram не установлен", android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            var showAdvanced by remember { mutableStateOf(false) }
            ExpandableSection(
                title = "ADVANCED SETTINGS",
                icon = Icons.Default.SettingsApplications,
                isExpanded = showAdvanced,
                onToggle = { showAdvanced = !showAdvanced }
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    AutoConnectCard(context = context)
                    
                    val pm = context.getSystemService(android.os.PowerManager::class.java)
                    val isIgnoringBattery = pm?.isIgnoringBatteryOptimizations(context.packageName) == true
                    if (!isIgnoringBattery) {
                        BatteryOptimizationInfoCard(context = context)
                    }

                    AppFilterCard(context = context, onSettingsChanged = onRestart)
                    ExpertSettingsCard(context = context, isVpnActive = isActive)
                }
            }

                if (isActive && serviceStatuses.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(12.dp))
                    var showServices by remember { mutableStateOf(false) }
                    ExpandableSection(
                        title = "SERVICE MONITOR",
                        icon = Icons.Default.Info,
                        isExpanded = showServices,
                        onToggle = { showServices = !showServices }
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 8.dp)
                                .background(GentleLightPink.copy(alpha = 0.03f), RoundedCornerShape(16.dp))
                                .padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = if (lastCheckTime > 0) "UPDATED: ${SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(lastCheckTime))}" else "WAITING...",
                                    fontSize = 9.sp,
                                    color = GentleLightPink.copy(alpha = 0.4f),
                                    fontWeight = FontWeight.Bold
                                )
                                IconButton(
                                    onClick = { ServiceChecker.triggerCheck() },
                                    modifier = Modifier.size(24.dp)
                                ) {
                                    Icon(Icons.Default.Refresh, null, tint = GentleLightPink.copy(alpha = 0.5f), modifier = Modifier.size(16.dp))
                                }
                            }
                            serviceStatuses.forEach { status ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .background(GentleLightPink.copy(alpha = 0.02f), RoundedCornerShape(8.dp))
                                        .padding(horizontal = 12.dp, vertical = 10.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Column {
                                        Text(status.name, color = GentleLightPink, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                                        Text(status.url.removePrefix("https://").removePrefix("www."), color = GentleLightPink.copy(alpha = 0.3f), fontSize = 10.sp)
                                    }
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        if (status.isUp && status.latencyMs > 0) {
                                            Text("${status.latencyMs} ms", color = if (status.latencyMs < 300) Color(0xFF81C784) else Color(0xFFFFB74D), fontSize = 11.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(end = 8.dp))
                                        }
                                        Icon(if (status.isUp) Icons.Default.CheckCircle else Icons.Default.Cancel, null, tint = if (status.isUp) Color(0xFF81C784) else Color(0xFFE57373), modifier = Modifier.size(14.dp))
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (showStrategyStats) {
                StrategyStatsDialog { showStrategyStats = false }
            }
        }
    }
