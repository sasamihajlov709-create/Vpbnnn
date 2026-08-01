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
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Cancel

class MainActivity : ComponentActivity() {
    private fun formatBytes(bytes: Long) = ProxyStats.formatBytes(bytes)
    private val vpnLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
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
            val isVpnActive by PinkVpnService.isRunning.collectAsStateWithLifecycle(initialValue = false)
            
            LaunchedEffect(Unit) {
                if (autoConnect && !PinkVpnService.isRunning.value) {
                    toggleVpn(false) // start it if not active
                }
            }

            MyApplicationTheme(dynamicColor = false) {
                PinkProxyApp(
                    isActive = isVpnActive,
                    onToggle = { toggleVpn(isVpnActive) },
                    onRestart = { 
                        if (isVpnActive) {
                            stopVpnService()
                            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                                startVpnService()
                            }, 1000)
                        }
                    }
                )
            }
        }
    }

    private fun toggleVpn(isActive: Boolean) {
        if (isActive) {
            stopVpnService()
        } else {
            try {
                // Ensure we use the exact application context to avoid UID mismatch errors
                val vpnIntent = VpnService.prepare(applicationContext)
                if (vpnIntent != null) {
                    vpnLauncher.launch(vpnIntent)
                } else {
                    startVpnService()
                }
            } catch (e: SecurityException) {
                android.util.Log.e("MainActivity", "VPN preparation failed: UID/Package mismatch", e)
                android.widget.Toast.makeText(
                    this,
                    "Security Error: System UID mismatch. Please clear app cache or reinstall.",
                    android.widget.Toast.LENGTH_LONG
                ).show()
                
                // Fallback attempt with activity context
                try {
                    val intent = VpnService.prepare(this)
                    if (intent != null) vpnLauncher.launch(intent) else startVpnService()
                } catch(e2: Throwable) {
                    Log.e("MainActivity", "Secondary VPN prep failed", e2)
                }
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
fun PinkProxyApp(isActive: Boolean, onToggle: () -> Unit, onRestart: () -> Unit) {
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
    val isPanicMode by BypassConfig.isPanicModeFlow.collectAsStateWithLifecycle(initialValue = false)
    val stabilityScore by ProxyStats.stabilityScore.collectAsStateWithLifecycle(initialValue = 100)
    val currentMtu by BypassConfig.currentMtu.collectAsStateWithLifecycle(initialValue = 1400)
    val successRate by ProxyStats.successRate.collectAsStateWithLifecycle(initialValue = 100)
    var showStrategyMenu by remember { mutableStateOf(false) }
    
    var showDiagnostics by remember { mutableStateOf(false) }
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
            if (isActive) {
                StatusBadge(isProxyHealthy, isInternetUp, isProbing)
            } else {
                Text(
                    text = stringResource(R.string.status_ready),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = GentleMediumPink.copy(alpha = 0.5f),
                    letterSpacing = 2.sp
                )
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Power Button (The Heart)
            PowerButton(isActive, onToggle, infiniteTransition)

            Spacer(modifier = Modifier.height(32.dp))

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
fun PowerButton(isActive: Boolean, onToggle: () -> Unit, transition: InfiniteTransition) {
    val pulseScale by transition.animateFloat(
        initialValue = 1f,
        targetValue = if (isActive) 1.1f else 1f,
        animationSpec = infiniteRepeatable(tween(1500), RepeatMode.Reverse), label = ""
    )
    
    Box(contentAlignment = Alignment.Center, modifier = Modifier.size(180.dp)) {
        if (isActive) {
            Box(
                modifier = Modifier
                    .size(160.dp)
                    .scale(pulseScale)
                    .clip(CircleShape)
                    .background(GentleDarkPink.copy(alpha = 0.1f))
                    .border(2.dp, GentleDarkPink.copy(alpha = 0.2f), CircleShape)
            )
        }
        
        Surface(
            onClick = onToggle,
            shape = CircleShape,
            color = if (isActive) GentleDarkPink else Color.Black,
            tonalElevation = 8.dp,
            modifier = Modifier.size(120.dp).testTag("connect_button"),
            border = BorderStroke(1.dp, GentleLightPink.copy(alpha = 0.1f))
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = Icons.Default.PowerSettingsNew,
                    contentDescription = null,
                    tint = if (isActive) Color.White else GentleDarkPink,
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
        
        val path = androidx.compose.ui.graphics.Path()
        history.take(60).forEachIndexed { i, speed ->
            val x = width - (i * step)
            val y = (height - (speed.toFloat() / maxSpeed * height)).coerceIn(0f, height)
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        
        drawPath(
            path = path,
            color = GentleMediumPink,
            style = androidx.compose.ui.graphics.drawscope.Stroke(
                width = 2.dp.toPx(), 
                cap = androidx.compose.ui.graphics.StrokeCap.Round, 
                join = androidx.compose.ui.graphics.StrokeJoin.Round
            )
        )
        
        // Gradient fill
        val fillPath = androidx.compose.ui.graphics.Path().apply {
            addPath(path)
            lineTo(width - (history.take(60).size - 1) * step, height)
            lineTo(width, height)
            close()
        }
        drawPath(
            path = fillPath,
            brush = androidx.compose.ui.graphics.Brush.verticalGradient(
                colors = listOf(GentleMediumPink.copy(alpha = 0.3f), Color.Transparent),
                startY = 0f,
                endY = height
            )
        )
    }
}

@Composable
fun MetricsCard(speedText: String, bytesTransferred: String, sessionTime: String, connectivityScore: Int, successRate: Int, stabilityScore: Int, signalQuality: Int, mtu: Int, isPanicMode: Boolean, censorshipIntensity: Int) {
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
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp)
            .heightIn(max = 200.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(PureBlack)
            .border(1.dp, GentleMediumPink.copy(alpha = 0.1f), RoundedCornerShape(16.dp))
            .padding(12.dp)
            .verticalScroll(rememberScrollState())
    ) {
        (recovery + traffic).takeLast(20).reversed().forEach { log ->
            Text(
                text = log,
                fontSize = 9.sp,
                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                color = if (log.contains("Healing")) GentleLightPink else Color.White.copy(alpha = 0.4f),
                modifier = Modifier.padding(vertical = 2.dp)
            )
        }
    }
}

@Composable
fun AutoConnectCard(context: android.content.Context) {
    val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
    var autoConnect by remember { mutableStateOf(prefs.getBoolean("auto_connect_on_launch", true)) }
    var autoBoot by remember { mutableStateOf(prefs.getBoolean("auto_start_on_boot", true)) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .border(1.dp, GentleMediumPink.copy(alpha = 0.2f), RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Black.copy(alpha = 0.5f)
        )
    ) {
        Column {
            Row(
                modifier = Modifier
                    .padding(16.dp)
                    .fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.label_auto_connect),
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = GentleLightPink
                    )
                    Text(
                        text = stringResource(R.string.desc_auto_connect),
                        fontSize = 11.sp,
                        color = GentleLightPink.copy(alpha = 0.6f),
                        lineHeight = 14.sp
                    )
                }
                Switch(
                    checked = autoConnect,
                    onCheckedChange = {
                        autoConnect = it
                        prefs.edit { putBoolean("auto_connect_on_launch", it) }
                    },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = GentleMediumPink,
                        checkedTrackColor = GentleDarkPink
                    )
                )
            }
            
            HorizontalDivider(color = GentleMediumPink.copy(alpha = 0.1f))
            
            Row(
                modifier = Modifier
                    .padding(16.dp)
                    .fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Автозапуск после перезагрузки",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = GentleLightPink
                    )
                    Text(
                        text = "Включать VPN автоматически при включении устройства",
                        fontSize = 11.sp,
                        color = GentleLightPink.copy(alpha = 0.6f),
                        lineHeight = 14.sp
                    )
                }
                Switch(
                    checked = autoBoot,
                    onCheckedChange = {
                        autoBoot = it
                        prefs.edit { putBoolean("auto_start_on_boot", it) }
                    },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = GentleMediumPink,
                        checkedTrackColor = GentleDarkPink
                    )
                )
            }
        }
    }
}

@Composable
fun BatteryOptimizationInfoCard(context: android.content.Context) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .border(1.dp, Color(0xFFFFB74D).copy(alpha = 0.3f), RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Black.copy(alpha = 0.6f)
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Default.Warning,
                    contentDescription = null,
                    tint = Color(0xFFFFB74D),
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.label_battery_optimization),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFFFB74D)
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.desc_battery_optimization),
                fontSize = 11.sp,
                color = GentleLightPink.copy(alpha = 0.8f),
                lineHeight = 15.sp
            )
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = {
                    try {
                        val intent = Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                            data = "package:${context.packageName}".toUri()
                        }
                        context.startActivity(intent)
                    } catch (e: Throwable) {
                        try {
                            val intent = Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                data = "package:${context.packageName}".toUri()
                            }
                            context.startActivity(intent)
                        } catch (ex: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${ex.message}") }
                    }
                },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE65100)),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth().height(36.dp),
                contentPadding = PaddingValues(0.dp)
            ) {
                Text(stringResource(R.string.action_disable), fontSize = 12.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)
            }
        }
    }
}
@Composable
fun AppFilterCard(context: android.content.Context, onSettingsChanged: () -> Unit) {
    var showDialog by remember { mutableStateOf(false) }
    var selectedCount by remember { mutableStateOf(PinkVpnService.selectedPackages.size) }
    var isExcludeMode by remember { mutableStateOf(PinkVpnService.isExcludeMode) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .border(1.dp, GentleLightPink.copy(alpha = 0.2f), RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Black.copy(alpha = 0.5f)
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.label_app_filter),
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = GentleLightPink
                    )
                    Text(
                        text = stringResource(R.string.desc_app_filter),
                        fontSize = 11.sp,
                        color = GentleLightPink.copy(alpha = 0.6f),
                        lineHeight = 14.sp
                    )
                }
                Icon(
                    imageVector = Icons.Default.FilterList,
                    contentDescription = null,
                    tint = GentleLightPink,
                    modifier = Modifier.size(24.dp)
                )
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = if (isExcludeMode) stringResource(R.string.label_exclude_mode) else stringResource(R.string.label_include_mode),
                    fontSize = 12.sp,
                    color = GentleLightPink,
                    fontWeight = FontWeight.Medium
                )
                Switch(
                    checked = isExcludeMode,
                    onCheckedChange = {
                        isExcludeMode = it
                        PinkVpnService.isExcludeMode = it
                        PinkVpnService.saveFilterSettings(context)
                        onSettingsChanged()
                    },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = GentleLightPink,
                        checkedTrackColor = GentleDarkPink
                    )
                )
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            Button(
                onClick = { showDialog = true },
                colors = ButtonDefaults.buttonColors(containerColor = GentleDarkPink),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth().height(40.dp)
            ) {
                Text(
                    text = "${stringResource(R.string.action_select_apps)} ($selectedCount)",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = GentleLightPink
                )
            }

            if (!isExcludeMode && selectedCount == 0) {
                Text(
                    text = "WARNING: No apps selected in Include mode. VPN will not route any traffic.",
                    color = Color(0xFFE57373),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
        }
    }

    if (showDialog) {
        AppSelectionDialog(
            context = context,
            onDismiss = { showDialog = false },
            onAppsSelected = { count ->
                selectedCount = count
                PinkVpnService.saveFilterSettings(context)
                onSettingsChanged()
            }
        )
    }
}

data class AppEntry(
    val appInfo: android.content.pm.ApplicationInfo,
    val label: String,
    val packageName: String
)

@Composable
fun AppIconImage(context: android.content.Context, appInfo: android.content.pm.ApplicationInfo, label: String) {
    var iconDrawable by remember(appInfo.packageName) { mutableStateOf<android.graphics.drawable.Drawable?>(null) }
    
    LaunchedEffect(appInfo.packageName) {
        val drawable = withContext(ProxyDispatcher.io) {
            try {
                context.packageManager.getApplicationIcon(appInfo)
            } catch (e: Throwable) {
                null
            }
        }
        iconDrawable = drawable
    }
    
    if (iconDrawable != null) {
        AndroidView(
            factory = { ctx ->
                android.widget.ImageView(ctx).apply {
                    scaleType = android.widget.ImageView.ScaleType.FIT_CENTER
                }
            },
            update = { imageView ->
                imageView.setImageDrawable(iconDrawable)
            },
            modifier = Modifier.size(40.dp)
        )
    } else {
        Box(
            modifier = Modifier
                .size(40.dp)
                .background(GentleLightPink.copy(alpha = 0.1f), RoundedCornerShape(8.dp)),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = label.take(1).uppercase(),
                color = GentleLightPink,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@Composable
fun AppSelectionDialog(
    context: android.content.Context,
    onDismiss: () -> Unit,
    onAppsSelected: (Int) -> Unit
) {
    var searchQuery by remember { mutableStateOf("") }
    var apps by remember { mutableStateOf<List<AppEntry>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    val pm = context.packageManager
    val selectedSet = remember { androidx.compose.runtime.mutableStateListOf<String>().apply { addAll(PinkVpnService.selectedPackages) } }

    LaunchedEffect(Unit) {
        val installedApps = withContext(ProxyDispatcher.io) {
            @Suppress("QueryPermissionsNeeded")
            val packages = pm.getInstalledApplications(android.content.pm.PackageManager.GET_META_DATA)
            packages.filter { (it.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0 || it.packageName == "com.google.android.youtube" || it.packageName == "org.telegram.messenger" }
                .map { app ->
                    val label = app.loadLabel(pm).toString()
                    AppEntry(app, label, app.packageName)
                }
                .sortedBy { it.label }
        }
        apps = installedApps
        isLoading = false
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = Color.Black
        ) {
            Column(modifier = Modifier.fillMaxSize()) {
                // Header
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = GentleLightPink)
                    }
                    Text(
                        stringResource(R.string.action_select_apps),
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                        color = GentleLightPink
                    )
                }

                // Search
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        modifier = Modifier.weight(1f),
                        placeholder = { Text("Search apps...", color = GentleLightPink.copy(alpha = 0.5f)) },
                        colors = TextFieldDefaults.colors(
                            focusedContainerColor = GentleLightPink.copy(alpha = 0.05f),
                            unfocusedContainerColor = GentleLightPink.copy(alpha = 0.05f),
                            focusedIndicatorColor = GentleMediumPink,
                            unfocusedIndicatorColor = Color.Transparent,
                            cursorColor = GentleMediumPink,
                            focusedTextColor = GentleLightPink,
                            unfocusedTextColor = GentleLightPink
                        ),
                        shape = RoundedCornerShape(12.dp)
                    )
                    
                    Spacer(modifier = Modifier.width(8.dp))
                    
                    TextButton(onClick = {
                        if (selectedSet.isEmpty()) {
                            apps.forEach { 
                                if (!selectedSet.contains(it.packageName)) {
                                    selectedSet.add(it.packageName)
                                    PinkVpnService.selectedPackages.add(it.packageName)
                                }
                            }
                        } else {
                            selectedSet.clear()
                            PinkVpnService.selectedPackages.clear()
                        }
                        PinkVpnService.saveFilterSettings(context)
                        onAppsSelected(PinkVpnService.selectedPackages.size)
                    }) {
                        Text(
                            if (selectedSet.isEmpty()) "SELECT ALL" else "CLEAR",
                            color = GentleMediumPink,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                if (isLoading) {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = GentleMediumPink)
                    }
                } else {
                    val filteredApps = if (searchQuery.isEmpty()) apps else {
                        apps.filter { it.label.contains(searchQuery, ignoreCase = true) }
                    }

                    LazyColumn(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(top = 16.dp)
                    ) {
                        items(filteredApps) { entry ->
                            val pkg = entry.packageName
                            val isSelected = selectedSet.contains(pkg)

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        if (isSelected) {
                                            selectedSet.remove(pkg)
                                            PinkVpnService.selectedPackages.remove(pkg)
                                        } else {
                                            selectedSet.add(pkg)
                                            PinkVpnService.selectedPackages.add(pkg)
                                        }
                                        PinkVpnService.saveFilterSettings(context)
                                        onAppsSelected(PinkVpnService.selectedPackages.size)
                                    }
                                    .padding(horizontal = 16.dp, vertical = 8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                // Dynamic high-performance asynchronous icon loading
                                AppIconImage(context, entry.appInfo, entry.label)
                                
                                Spacer(modifier = Modifier.width(16.dp))
                                
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = entry.label,
                                        color = GentleLightPink,
                                        fontSize = 15.sp,
                                        fontWeight = FontWeight.Medium
                                    )
                                    Text(
                                        text = pkg,
                                        color = GentleLightPink.copy(alpha = 0.5f),
                                        fontSize = 12.sp
                                    )
                                }
                                
                                Checkbox(
                                    checked = isSelected,
                                    onCheckedChange = null, // Handled by row click
                                    colors = CheckboxDefaults.colors(
                                        checkedColor = GentleMediumPink,
                                        uncheckedColor = GentleLightPink.copy(alpha = 0.3f)
                                    )
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ExpertSettingsCard(
    context: android.content.Context,
    isVpnActive: Boolean
) {
    var expanded by remember { mutableStateOf(false) }

    // Read volatile settings into local Compose state so sliders / switches reflect changes in real-time
    var isAutoTuning by remember { mutableStateOf(BypassConfig.isAutoTuning) }
    var frag1 by remember { mutableStateOf(BypassConfig.frag1.toFloat()) }
    var frag2 by remember { mutableStateOf(BypassConfig.frag2.toFloat()) }
    var frag3 by remember { mutableStateOf(BypassConfig.frag3.toFloat()) }
    var delay1 by remember { mutableStateOf(BypassConfig.delay1.toFloat()) }
    var delay2 by remember { mutableStateOf(BypassConfig.delay2.toFloat()) }
    var fakeTtl by remember { mutableStateOf(BypassConfig.fakeTtl.toFloat()) }

    var dnsMode by remember { mutableStateOf(RobustResolver.dnsMode) }
    var customDnsIp by remember { mutableStateOf(RobustResolver.customDnsIp) }
    var autoConnect by remember { mutableStateOf(context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE).getBoolean("auto_connect_on_launch", false)) }
    var isDiagnosticModeState by remember { mutableStateOf(BypassConfig.isDiagnosticMode) }

    val customServices by ServiceChecker.customServices.collectAsStateWithLifecycle(initialValue = emptyList())
    var newServiceName by remember { mutableStateOf("") }
    var newServiceUrl by remember { mutableStateOf("") }

    // Sync state if BypassConfig or RobustResolver gets changed from outside (e.g. on service start)
    LaunchedEffect(expanded) {
        if (expanded) {
            isAutoTuning = BypassConfig.isAutoTuning
            frag1 = BypassConfig.frag1.toFloat()
            frag2 = BypassConfig.frag2.toFloat()
            frag3 = BypassConfig.frag3.toFloat()
            delay1 = BypassConfig.delay1.toFloat()
            delay2 = BypassConfig.delay2.toFloat()
            fakeTtl = BypassConfig.fakeTtl.toFloat()
            dnsMode = RobustResolver.dnsMode
            customDnsIp = RobustResolver.customDnsIp
            isDiagnosticModeState = BypassConfig.isDiagnosticMode
            ServiceChecker.loadCustomServices(context)
        }
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .border(1.dp, GentleMediumPink.copy(alpha = 0.3f), RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = PureBlack.copy(alpha = 0.8f)
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Clickable header row to expand/collapse
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { expanded = !expanded }
                    .padding(vertical = 4.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.Settings,
                        contentDescription = null,
                        tint = GentleMediumPink,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "🛠️ ИНЖЕНЕРНАЯ ПАНЕЛЬ / EXPERT TUNING",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = GentleMediumPink
                    )
                }
                Icon(
                    imageVector = if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    contentDescription = null,
                    tint = GentleMediumPink.copy(alpha = 0.7f)
                )
            }

            if (expanded) {
                HorizontalDivider(
                    color = GentleMediumPink.copy(alpha = 0.2f),
                    thickness = 1.dp,
                    modifier = Modifier.padding(vertical = 12.dp)
                )

                // Auto Connect Toggle
                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "AUTO-CONNECT ON LAUNCH",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = GentleLightPink
                        )
                        Text(
                            text = "Автоматический запуск при открытии приложения",
                            fontSize = 9.sp,
                            color = GentleLightPink.copy(alpha = 0.4f)
                        )
                    }
                    Switch(
                        checked = autoConnect,
                        onCheckedChange = { 
                            autoConnect = it
                            context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
                                .edit { putBoolean("auto_connect_on_launch", it) }
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = GentleMediumPink,
                            checkedTrackColor = GentleMediumPink.copy(alpha = 0.5f)
                        )
                    )
                }

                // Auto-Tuning Toggle
                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "DPI AUTO-TUNING",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = GentleLightPink
                        )
                        Text(
                            text = "Автоматическая подстройка DPI",
                            fontSize = 9.sp,
                            color = GentleLightPink.copy(alpha = 0.4f)
                        )
                    }
                    Switch(
                        checked = isAutoTuning,
                        onCheckedChange = { 
                            isAutoTuning = it
                            BypassConfig.isAutoTuning = it
                            BypassConfig.saveTuningSettings(context)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = GentleMediumPink,
                            checkedTrackColor = GentleMediumPink.copy(alpha = 0.5f)
                        )
                    )
                }
                
                // QUIC Blocking Toggle
                var blockQuicState by remember { mutableStateOf(BypassConfig.blockQuic) }
                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "BLOCK QUIC (UDP 443)",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = GentleLightPink
                        )
                        Text(
                            text = "Блокировка QUIC (IPv6). Для IPv4 рекомендуется отключить QUIC в браузере (chrome://flags)",
                            fontSize = 9.sp,
                            color = GentleLightPink.copy(alpha = 0.5f)
                        )
                    }
                    Switch(
                        checked = blockQuicState,
                        onCheckedChange = { 
                            blockQuicState = it
                            BypassConfig.blockQuic = it
                            BypassConfig.saveTuningSettings(context)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = GentleMediumPink,
                            checkedTrackColor = GentleMediumPink.copy(alpha = 0.5f)
                        )
                    )
                }

                // Verbose Diagnostic Logs Toggle
                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "VERBOSE DIAGNOSTIC LOGS",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = GentleLightPink
                        )
                        Text(
                            text = "Детальный вывод ошибок обхода DNS/DPI в лог-анализатор",
                            fontSize = 9.sp,
                            color = GentleLightPink.copy(alpha = 0.5f)
                        )
                    }
                    Switch(
                        checked = isDiagnosticModeState,
                        onCheckedChange = { 
                            isDiagnosticModeState = it
                            BypassConfig.isDiagnosticMode = it
                            BypassConfig.saveTuningSettings(context)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = GentleMediumPink,
                            checkedTrackColor = GentleMediumPink.copy(alpha = 0.5f)
                        )
                    )
                }
                
                // Reset Statistics Button
                Button(
                    onClick = {
                        ProxyStats.reset(clearLog = true)
                        BypassConfig.resetCaches()
                        android.widget.Toast.makeText(context, "All caches and stats cleared", android.widget.Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp, bottom = 16.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.Red.copy(alpha = 0.15f),
                        contentColor = Color.White.copy(alpha = 0.9f)
                    ),
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, Color.Red.copy(alpha = 0.3f))
                ) {
                    Icon(Icons.Default.Refresh, null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("CLEAR ALL STATISTICS", fontSize = 10.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
                }

                HorizontalDivider(
                    color = GentleMediumPink.copy(alpha = 0.15f),
                    thickness = 1.dp,
                    modifier = Modifier.padding(bottom = 12.dp)
                )

                // 1. DNS Settings Section
                Text(
                    text = "1. НАСТРОЙКИ SECURE DNS (DoH)",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = GentleLightPink.copy(alpha = 0.9f),
                    modifier = Modifier.padding(bottom = 6.dp)
                )

                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    val smartBg = if (dnsMode == "Smart DoH") GentleDarkPink else GentleMediumPink.copy(alpha = 0.1f)
                    val customBg = if (dnsMode == "Custom") GentleDarkPink else GentleMediumPink.copy(alpha = 0.1f)

                    Button(
                        onClick = {
                            dnsMode = "Smart DoH"
                            RobustResolver.saveDnsSettings(context, "Smart DoH", customDnsIp)
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = smartBg),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.weight(1f).height(36.dp),
                        contentPadding = PaddingValues(0.dp)
                    ) {
                        Text("Smart DoH", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)
                    }

                    Button(
                        onClick = {
                            dnsMode = "Custom"
                            RobustResolver.saveDnsSettings(context, "Custom", customDnsIp)
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = customBg),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.weight(1f).height(36.dp),
                        contentPadding = PaddingValues(0.dp)
                    ) {
                        Text("Custom DNS/DoH", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)
                    }
                }

                if (dnsMode == "Custom") {
                    OutlinedTextField(
                        value = customDnsIp,
                        onValueChange = {
                            customDnsIp = it
                            RobustResolver.saveDnsSettings(context, "Custom", it)
                        },
                        label = { Text("DNS IP (e.g. 9.9.9.9) or DoH URL", color = GentleMediumPink.copy(alpha = 0.5f), fontSize = 11.sp) },
                        textStyle = androidx.compose.ui.text.TextStyle(color = GentleLightPink, fontSize = 12.sp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = GentleMediumPink,
                            unfocusedBorderColor = GentleMediumPink.copy(alpha = 0.4f),
                            cursorColor = GentleMediumPink
                        ),
                        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                        singleLine = true
                    )
                }

                HorizontalDivider(
                    color = GentleMediumPink.copy(alpha = 0.1f),
                    thickness = 1.dp,
                    modifier = Modifier.padding(vertical = 12.dp)
                )

                // 2. Auto-Tuning Configuration
                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 6.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "2. ПАРАМЕТРЫ ОБХОДА DPI",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = GentleLightPink.copy(alpha = 0.9f)
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "Auto-Tuning",
                            fontSize = 10.sp,
                            color = GentleLightPink.copy(alpha = 0.6f),
                            modifier = Modifier.padding(end = 6.dp)
                        )
                        Switch(
                            checked = isAutoTuning,
                            onCheckedChange = {
                                isAutoTuning = it
                                BypassConfig.isAutoTuning = it
                                BypassConfig.saveTuningSettings(context)
                                if (it) {
                                    try {
                                        val intent = Intent(context, PinkVpnService::class.java).apply {
                                            action = "CHANGE_STRATEGY"
                                        }
                                        androidx.core.content.ContextCompat.startForegroundService(context, intent)
                                    } catch (e: Throwable) {
                                        Log.e("MainActivity", "Failed to change strategy: ${e.message}")
                                    }
                                }
                            },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = GentleMediumPink,
                                checkedTrackColor = GentleDarkPink,
                                uncheckedThumbColor = Color.Gray,
                                uncheckedTrackColor = Color.DarkGray
                            ),
                            modifier = Modifier.scale(0.7f)
                        )
                    }
                }

                if (!isAutoTuning) {
                    Text(
                        text = "Ручной режим активен. Ползунки управляют фрагментацией и задержкой пакетов ClientHello в реальном времени.",
                        fontSize = 10.sp,
                        color = GentleLightPink.copy(alpha = 0.5f),
                        lineHeight = 14.sp,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )

                    // Param Sliders
                    // 1. frag1
                    Column(modifier = Modifier.padding(vertical = 4.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Размер 1-го фрагмента (frag1):", fontSize = 10.sp, color = GentleLightPink.copy(alpha = 0.8f))
                            Text("${frag1.toInt()} байт", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink)
                        }
                        Slider(
                            value = frag1,
                            onValueChange = {
                                frag1 = it
                                BypassConfig.frag1 = it.toInt()
                                BypassConfig.saveTuningSettings(context)
                            },
                            valueRange = 1f..100f,
                            colors = SliderDefaults.colors(
                                thumbColor = GentleMediumPink,
                                activeTrackColor = GentleDarkPink
                            )
                        )
                    }

                    // 2. frag2
                    Column(modifier = Modifier.padding(vertical = 4.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Размер 2-го фрагмента (frag2):", fontSize = 10.sp, color = GentleLightPink.copy(alpha = 0.8f))
                            Text("${frag2.toInt()} байт", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink)
                        }
                        Slider(
                            value = frag2,
                            onValueChange = {
                                frag2 = it
                                BypassConfig.frag2 = it.toInt()
                                BypassConfig.saveTuningSettings(context)
                            },
                            valueRange = 1f..100f,
                            colors = SliderDefaults.colors(
                                thumbColor = GentleMediumPink,
                                activeTrackColor = GentleDarkPink
                            )
                        )
                    }

                    // 3. delay1
                    Column(modifier = Modifier.padding(vertical = 4.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Задержка 1-го фрагмента (delay1):", fontSize = 10.sp, color = GentleLightPink.copy(alpha = 0.8f))
                            Text("${delay1.toInt()} мс", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink)
                        }
                        Slider(
                            value = delay1,
                            onValueChange = {
                                delay1 = it
                                BypassConfig.delay1 = it.toLong()
                                BypassConfig.saveTuningSettings(context)
                            },
                            valueRange = 0f..200f,
                            colors = SliderDefaults.colors(
                                thumbColor = GentleMediumPink,
                                activeTrackColor = GentleDarkPink
                            )
                        )
                    }

                    // 4. delay2
                    Column(modifier = Modifier.padding(vertical = 4.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Задержка 2-го фрагмента (delay2):", fontSize = 10.sp, color = GentleLightPink.copy(alpha = 0.8f))
                            Text("${delay2.toInt()} мс", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink)
                        }
                        Slider(
                            value = delay2,
                            onValueChange = {
                                delay2 = it
                                BypassConfig.delay2 = it.toLong()
                                BypassConfig.saveTuningSettings(context)
                            },
                            valueRange = 0f..200f,
                            colors = SliderDefaults.colors(
                                thumbColor = GentleMediumPink,
                                activeTrackColor = GentleDarkPink
                            )
                        )
                    }

                    // 5. fakeTtl
                    Column(modifier = Modifier.padding(vertical = 4.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("IP TTL для фейк-пакетов (fakeTtl):", fontSize = 10.sp, color = GentleLightPink.copy(alpha = 0.8f))
                            Text("${fakeTtl.toInt()}", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink)
                        }
                        Slider(
                            value = fakeTtl,
                            onValueChange = {
                                fakeTtl = it
                                BypassConfig.fakeTtl = it.toInt()
                                BypassConfig.saveTuningSettings(context)
                            },
                            valueRange = 1f..30f,
                            colors = SliderDefaults.colors(
                                thumbColor = GentleMediumPink,
                                activeTrackColor = GentleDarkPink
                            )
                        )
                    }
                } else {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(GentleLightPink.copy(alpha = 0.05f), RoundedCornerShape(8.dp))
                            .padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "ℹ️ Автоматический тюнинг параметров активен. Система динамически подбирает задержки (delay: ${delay1.toInt()}/${delay2.toInt()}ms) и размеры фрагментов (frag: ${frag1.toInt()}/${frag2.toInt()}) для текущей стратегии обхода DPI.",
                            fontSize = 10.sp,
                            color = GentleLightPink.copy(alpha = 0.7f),
                            lineHeight = 14.sp
                        )
                    }
                }

                HorizontalDivider(
                    color = GentleMediumPink.copy(alpha = 0.1f),
                    thickness = 1.dp,
                    modifier = Modifier.padding(vertical = 12.dp)
                )

                // DPI Strategy Selection
                Text(
                    text = "3. ВЫБОР СТРАТЕГИИ ОБХОДА",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = GentleLightPink.copy(alpha = 0.9f),
                    modifier = Modifier.padding(bottom = 6.dp)
                )
                
                var showStrategyMenuLocal by remember { mutableStateOf(false) }
                val currentStrategy by BypassConfig.strategy.collectAsStateWithLifecycle(initialValue = BypassStrategy.SNI_SPLIT)
                
                Box {
                    Button(
                        onClick = { showStrategyMenuLocal = true },
                        colors = ButtonDefaults.buttonColors(containerColor = GentleMediumPink.copy(alpha = 0.1f)),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth().height(40.dp),
                        border = BorderStroke(1.dp, GentleMediumPink.copy(alpha = 0.2f))
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(currentStrategy.name.replace("_", " "), fontSize = 11.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)
                            Spacer(Modifier.width(8.dp))
                            Icon(Icons.Default.ArrowDropDown, null, tint = GentleMediumPink, modifier = Modifier.size(16.dp))
                        }
                    }
                    
                    DropdownMenu(
                        expanded = showStrategyMenuLocal,
                        onDismissRequest = { showStrategyMenuLocal = false },
                        modifier = Modifier.background(PureBlack).border(1.dp, GentleMediumPink.copy(alpha = 0.2f))
                    ) {
                        BypassStrategy.entries.forEach { strategy ->
                            DropdownMenuItem(
                                text = { Text(strategy.name.replace("_", " "), color = GentleLightPink, fontSize = 11.sp) },
                                onClick = {
                                    showStrategyMenuLocal = false
                                    BypassConfig.setGlobalStrategy(strategy)
                                    BypassConfig.saveTuningSettings(context)
                                    // Trigger immediate change if VPN is running
                                    if (isVpnActive) {
                                        try {
                                            val intent = Intent(context, PinkVpnService::class.java).apply {
                                                action = "CHANGE_STRATEGY"
                                            }
                                            androidx.core.content.ContextCompat.startForegroundService(context, intent)
                                        } catch (e: Throwable) {
                                            Log.e("MainActivity", "Failed to change strategy: ${e.message}")
                                        }
                                    }
                                }
                            )
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(12.dp))

                // 4. Custom Websites Monitor
                Text(
                    text = "4. МОНИТОРИНГ СОБСТВЕННЫХ САЙТОВ",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = GentleLightPink.copy(alpha = 0.9f),
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                Text(
                    text = "Добавьте сайт, который хотите разблокировать, чтобы авто-пилот отслеживал его доступность и подбирал лучшие стратегии.",
                    fontSize = 10.sp,
                    color = GentleLightPink.copy(alpha = 0.5f),
                    lineHeight = 14.sp,
                    modifier = Modifier.padding(bottom = 8.dp)
                )

                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = newServiceName,
                        onValueChange = { newServiceName = it },
                        label = { Text("Название (e.g. Meduza)", color = GentleMediumPink.copy(alpha = 0.5f), fontSize = 10.sp) },
                        textStyle = androidx.compose.ui.text.TextStyle(color = GentleLightPink, fontSize = 11.sp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = GentleMediumPink,
                            unfocusedBorderColor = GentleMediumPink.copy(alpha = 0.4f),
                            cursorColor = GentleMediumPink
                        ),
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )

                    OutlinedTextField(
                        value = newServiceUrl,
                        onValueChange = { newServiceUrl = it },
                        label = { Text("https://...", color = GentleMediumPink.copy(alpha = 0.5f), fontSize = 10.sp) },
                        textStyle = androidx.compose.ui.text.TextStyle(color = GentleLightPink, fontSize = 11.sp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = GentleMediumPink,
                            unfocusedBorderColor = GentleMediumPink.copy(alpha = 0.4f),
                            cursorColor = GentleMediumPink
                        ),
                        modifier = Modifier.weight(1.5f),
                        singleLine = true
                    )

                    IconButton(
                        onClick = {
                            var urlClean = newServiceUrl.trim()
                            val nameClean = newServiceName.trim()
                            if (nameClean.isNotEmpty() && urlClean.isNotEmpty()) {
                                if (!urlClean.startsWith("http://") && !urlClean.startsWith("https://")) {
                                    urlClean = "https://$urlClean"
                                }
                                ServiceChecker.addCustomService(context, nameClean, urlClean)
                                newServiceName = ""
                                newServiceUrl = ""
                            }
                        },
                        modifier = Modifier
                            .size(40.dp)
                            .background(GentleDarkPink, RoundedCornerShape(8.dp))
                    ) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = "Add",
                            tint = GentleLightPink,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }

                if (customServices.isNotEmpty()) {
                    Text(
                        text = "Добавленные сайты (нажмите корзину для удаления):",
                        fontSize = 10.sp,
                        color = GentleLightPink.copy(alpha = 0.7f),
                        modifier = Modifier.padding(vertical = 4.dp)
                    )

                    Column(
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.fillMaxWidth().padding(top = 4.dp)
                    ) {
                        customServices.forEach { service ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(GentleLightPink.copy(alpha = 0.04f), RoundedCornerShape(8.dp))
                                    .padding(horizontal = 10.dp, vertical = 6.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(service.first, color = GentleLightPink, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                    Text(service.second, color = GentleLightPink.copy(alpha = 0.4f), fontSize = 9.sp)
                                }
                                IconButton(
                                    onClick = { ServiceChecker.removeCustomService(context, service.first) },
                                    modifier = Modifier.size(28.dp)
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Delete,
                                        contentDescription = "Delete",
                                        tint = Color(0xFFE57373),
                                        modifier = Modifier.size(16.dp)
                                    )
                                }
                            }
                        }
                    }
                }

                HorizontalDivider(
                    color = GentleMediumPink.copy(alpha = 0.1f),
                    thickness = 1.dp,
                    modifier = Modifier.padding(vertical = 12.dp)
                )

                // 5. Force Reset / Clear Scores
                Text(
                    text = "5. СБРОС И ПЕРЕЗАГРУЗКА",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = GentleLightPink.copy(alpha = 0.9f),
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                Text(
                    text = stringResource(R.string.desc_clear_scores),
                    fontSize = 10.sp,
                    color = GentleLightPink.copy(alpha = 0.5f),
                    lineHeight = 14.sp,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                Button(
                    onClick = {
                        BypassConfig.clearScores(context)
                        try {
                            val intent = Intent(context, PinkVpnService::class.java).apply {
                                action = "RESTART"
                            }
                            androidx.core.content.ContextCompat.startForegroundService(context, intent)
                        } catch (e: Throwable) {
                            Log.e("MainActivity", "Failed to restart VPN: ${e.message}")
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = GentleDarkPink),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth().height(36.dp),
                    contentPadding = PaddingValues(0.dp)
                ) {
                    Text(stringResource(R.string.action_clear_scores), fontSize = 11.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)
                }
            }
        }
    }
}

@Composable
fun StrategyStatsDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    var metrics by remember { mutableStateOf(BypassConfig.getStrategyMetrics()) }
    
    // Refresh periodically
    LaunchedEffect(Unit) {
        while (true) {
            delay(2000)
            metrics = BypassConfig.getStrategyMetrics()
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth(0.95f)
                .fillMaxHeight(0.85f)
                .clip(RoundedCornerShape(24.dp))
                .border(1.dp, GentleMediumPink.copy(alpha = 0.2f), RoundedCornerShape(24.dp)),
            color = PureBlack
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "STRATEGY TOURNAMENT BOARD",
                            fontSize = 16.sp,
                            fontWeight = FontWeight.ExtraBold,
                            color = GentleLightPink
                        )
                        Text(
                            text = "Аналитика обхода DPI в реальном времени",
                            fontSize = 11.sp,
                            color = GentleLightPink.copy(alpha = 0.5f)
                        )
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Cancel, null, tint = GentleMediumPink)
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(metrics) { metric ->
                        StrategyMetricItem(metric)
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Button(
                    onClick = { ServiceChecker.runActiveProbing(context) },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = GentleMediumPink.copy(alpha = 0.2f)),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Refresh, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("RUN FAST TOURNAMENT RACE", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)
                    }
                }
            }
        }
    }
}

@Composable
fun StrategyMetricItem(metric: StrategyMetric) {
    val scoreColor = when {
        metric.score > 150 -> Color(0xFF81C784)
        metric.score > 80 -> Color(0xFFFFF176)
        else -> Color(0xFFE57373)
    }
    
    Surface(
        color = GentleLightPink.copy(alpha = 0.05f),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = metric.strategy.name.replace("_", " "),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = GentleLightPink
                )
                Surface(
                    color = scoreColor.copy(alpha = 0.2f),
                    shape = CircleShape,
                    modifier = Modifier.size(width = 48.dp, height = 20.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Text(
                            text = "${metric.score}",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.ExtraBold,
                            color = scoreColor
                        )
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                MetricSmallDetail("SUCCESS", "${metric.successes}", Color(0xFF81C784))
                MetricSmallDetail("FAIL", "${metric.failures}", Color(0xFFE57373))
                MetricSmallDetail("AVG RTT", "${metric.avgRtt}ms", GentleLightPink.copy(alpha = 0.7f))
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            // Success rate bar
            val total = (metric.successes + metric.failures).coerceAtLeast(1)
            val rate = (metric.successes.toFloat() / total.toFloat())
            LinearProgressIndicator(
                progress = { rate },
                modifier = Modifier.fillMaxWidth().height(4.dp).clip(CircleShape),
                color = scoreColor,
                trackColor = GentleLightPink.copy(alpha = 0.1f)
            )
        }
    }
}

@Composable
fun MetricSmallDetail(label: String, value: String, color: Color) {
    Column {
        Text(label, fontSize = 8.sp, fontWeight = FontWeight.Bold, color = GentleLightPink.copy(alpha = 0.4f))
        Text(value, fontSize = 10.sp, fontWeight = FontWeight.ExtraBold, color = color)
    }
}
