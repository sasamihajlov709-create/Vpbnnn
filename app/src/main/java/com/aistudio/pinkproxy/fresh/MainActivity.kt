package com.aistudio.pinkproxy.fresh

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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.SimpleDateFormat
import java.util.*
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.ui.viewinterop.AndroidView
import com.aistudio.pinkproxy.fresh.ui.theme.MyApplicationTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import android.net.Uri
import android.provider.Settings
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        enableEdgeToEdge()
        
        try {
            PinkVpnService.loadFilterSettings(this)
            BypassConfig.loadTuningSettings(this)
            RobustResolver.loadDnsSettings(this)
        } catch (e: Exception) {
            android.util.Log.e("MainActivity", "Error loading initial settings", e)
        }
        
        val prefs = getSharedPreferences("pink_proxy_settings", MODE_PRIVATE)
        val autoConnect = prefs.getBoolean("auto_connect_on_launch", true)
        
        setContent {
            val isVpnActive by PinkVpnService.isRunning.collectAsStateWithLifecycle(initialValue = false)
            
            LaunchedEffect(Unit) {
                if (autoConnect && !isVpnActive) {
                    toggleVpn(false) // toggleVpn(false) will start it if not active
                }
                RobustResolver.updatePublicIpSubnet(null)
                RobustResolver.startWarmup(null)
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
                val intent = VpnService.prepare(this)
                if (intent != null) {
                    vpnLauncher.launch(intent)
                } else {
                    startVpnService()
                }
            } catch (e: SecurityException) {
                android.util.Log.e("MainActivity", "VPN preparation failed", e)
                android.widget.Toast.makeText(
                    this,
                    "VPN setup failed: package/UID system conflict. Please restart the application.",
                    android.widget.Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, PinkVpnService::class.java)
        androidx.core.content.ContextCompat.startForegroundService(this, intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, PinkVpnService::class.java).apply {
            action = "STOP"
        }
        startService(intent)
    }
}

@Composable
fun PinkProxyApp(isActive: Boolean, onToggle: () -> Unit, onRestart: () -> Unit) {
    val bgColor1 = Color(0xFF1a0510) // Almost black with pink tint
    val bgColor2 = Color(0xFF2a0a18) // Very dark pink/burgundy
    val bgColor3 = Color(0xFF381220) // Dark muted pink
    
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
    val speedHistory by ProxyStats.speedHistory.collectAsStateWithLifecycle(initialValue = emptyList())
    val errorCount by ProxyStats.errors.collectAsStateWithLifecycle(initialValue = 0L)
    val censorshipIntensity by ProxyStats.censorshipIntensity.collectAsStateWithLifecycle(initialValue = 0)
    val serviceStatuses by ServiceChecker.statuses.collectAsStateWithLifecycle(initialValue = emptyList())
    val isProxyHealthy by ServiceChecker.proxyHealth.collectAsStateWithLifecycle(initialValue = true)
    val isInternetUp by ServiceChecker.internetAvailable.collectAsStateWithLifecycle(initialValue = true)
    val isStalled by ServiceChecker.isStalled.collectAsStateWithLifecycle(initialValue = false)
    val isProbing by ServiceChecker.isProbingState.collectAsStateWithLifecycle(initialValue = false)
    val lastCheckTime by ServiceChecker.lastCheckTime.collectAsStateWithLifecycle(initialValue = 0L)

    val recoveryLog by ProxyStats.recoveryLog.collectAsStateWithLifecycle(initialValue = emptyList())
    val trafficLog by ProxyStats.trafficLog.collectAsStateWithLifecycle(initialValue = emptyList())
    val activeStrategy by BypassConfig.strategy.collectAsStateWithLifecycle(initialValue = BypassStrategy.SNI_SPLIT)
    val signalQuality by ProxyStats.signalQuality.collectAsStateWithLifecycle(initialValue = 100)
    val currentNetworkType by BypassConfig.currentNetworkType.collectAsStateWithLifecycle(initialValue = NetworkType.UNKNOWN)
    val currentRttMs by BypassConfig.currentRttMs.collectAsStateWithLifecycle(initialValue = 50L)
    val currentFragSize by BypassConfig.currentFragSizeState.collectAsStateWithLifecycle(initialValue = 1)
    val topHosts by ProxyStats.topHosts.collectAsStateWithLifecycle(initialValue = emptyList())
    val pool8kSize by ProxyStats.pool8kSize.collectAsStateWithLifecycle(initialValue = 0)
    val pool16kSize by ProxyStats.pool16kSize.collectAsStateWithLifecycle(initialValue = 0)
    val congestionWindow by ProxyStats.congestionWindow.collectAsStateWithLifecycle(initialValue = 10)
    val dnsSuccess by ProxyStats.dnsSuccessCount.collectAsStateWithLifecycle(initialValue = 0L)
    val dnsFailure by ProxyStats.dnsFailureCount.collectAsStateWithLifecycle(initialValue = 0L)
    var showStrategyMenu by remember { mutableStateOf(false) }
    
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
        
        // Blurred Glass Background Layer
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp)
                .clip(RoundedCornerShape(32.dp))
                .background(Color.Black.copy(alpha = 0.2f))
                .blur(radius = 48.dp)
        )

        // Content Layer - Scrollable to prevent clipping or overflow on compact devices
        val scrollState = rememberScrollState()
        Column(
            modifier = Modifier
                .fillMaxHeight()
                .widthIn(max = 600.dp)
                .align(Alignment.TopCenter)
                .verticalScroll(scrollState)
                .padding(WindowInsets.safeDrawing.asPaddingValues())
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Top
        ) {
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = stringResource(R.string.app_name),
                fontSize = 42.sp,
                fontWeight = FontWeight.Bold,
                color = Color(0xFFF8BBD0),
                modifier = Modifier.padding(bottom = 8.dp)
            )
            
            Text(
                text = stringResource(R.string.label_dpi_bypass),
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium,
                color = Color(0xFFF48FB1),
                modifier = Modifier.padding(bottom = 12.dp)
            )

            if (isActive) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .padding(bottom = 24.dp)
                        .background(
                            color = (if (isProxyHealthy && isInternetUp) Color(0xFF81C784) else Color(0xFFE57373)).copy(alpha = 0.15f),
                            shape = RoundedCornerShape(12.dp)
                        )
                        .padding(horizontal = 12.dp, vertical = 6.dp)
                ) {
                    val pulseTransition = rememberInfiniteTransition(label = "pulse")
                    val pulseAlpha by pulseTransition.animateFloat(
                        initialValue = 0.4f,
                        targetValue = 1.0f,
                        animationSpec = infiniteRepeatable(tween(800, easing = LinearEasing), repeatMode = RepeatMode.Reverse),
                        label = "pulseAlpha"
                    )
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .background(
                                color = (if (!isInternetUp) Color(0xFF9E9E9E) else if (isProxyHealthy) Color(0xFF81C784) else Color(0xFFE57373)).copy(alpha = if (isActive && isProxyHealthy) pulseAlpha else 1f),
                                shape = CircleShape
                            )
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = when {
                            !isInternetUp -> stringResource(R.string.status_no_internet)
                            isProbing -> "AUTOPILOT PROBING STRATEGIES..."
                            isStalled -> "TRAFFIC STALL DETECTED"
                            !isProxyHealthy -> stringResource(R.string.status_recovery)
                            else -> if (isActive && isProxyHealthy) stringResource(R.string.status_autopilot) + " & PREFETCH" else stringResource(R.string.status_autopilot)
                        },
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = when {
                            !isInternetUp -> Color(0xFF9E9E9E)
                            isProbing -> Color(0xFF64B5F6) // Blue for active work
                            isStalled -> Color(0xFFFFB74D) // Orange for warning
                            isProxyHealthy -> Color(0xFF81C784)
                            else -> Color(0xFFE57373)
                        },
                        letterSpacing = 1.sp
                    )
                }
            } else {
                Spacer(modifier = Modifier.height(48.dp))
            }

            // Stats row
            if (isActive) {
                val connectivityScore by ServiceChecker.connectivityScore.collectAsStateWithLifecycle(initialValue = 0)
                
                var isIgnoringBattery by remember { mutableStateOf(true) }
                val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current
                
                DisposableEffect(lifecycleOwner) {
                    val observer = androidx.lifecycle.LifecycleEventObserver { _, event ->
                        if (event == androidx.lifecycle.Lifecycle.Event.ON_RESUME) {
                            val pm = context.getSystemService(android.os.PowerManager::class.java)
                            isIgnoringBattery = pm?.isIgnoringBatteryOptimizations(context.packageName) == true
                        }
                    }
                    lifecycleOwner.lifecycle.addObserver(observer)
                    onDispose {
                        lifecycleOwner.lifecycle.removeObserver(observer)
                    }
                }
                
                if (!isIgnoringBattery) {
                    Text(
                        text = stringResource(R.string.msg_optimize_battery),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFFFB74D),
                        modifier = Modifier
                            .padding(bottom = 12.dp)
                            .clickable {
                                try {
                                    val intent = Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                                        data = android.net.Uri.parse("package:${context.packageName}")
                                    }
                                    context.startActivity(intent)
                                } catch (e: Exception) {
                                    try {
                                        val intent = Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                            data = android.net.Uri.parse("package:${context.packageName}")
                                        }
                                        context.startActivity(intent)
                                    } catch (ex: Exception) {
                                        android.widget.Toast.makeText(context, "Battery settings are not accessible", android.widget.Toast.LENGTH_SHORT).show()
                                    }
                                }
                            }
                            .background(Color(0xFFFFB74D).copy(alpha = 0.1f), RoundedCornerShape(4.dp))
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }

                // Check and request notification permission
                // Moved to root of composable

                Row(
                    modifier = Modifier.padding(bottom = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // SOCKS5 Badge
                    Surface(
                        color = Color(0xFFCE93D8).copy(alpha = 0.1f),
                        shape = RoundedCornerShape(16.dp),
                        border = BorderStroke(1.dp, Color(0xFFCE93D8).copy(alpha = 0.3f))
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = Color(0xFFCE93D8),
                                modifier = Modifier.size(12.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                text = "SOCKS5 127.0.0.1:18080",
                                color = Color(0xFFCE93D8),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Medium
                            )
                        }
                    }
                    // Autopilot Badge
                    Surface(
                        color = Color(0xFFF48FB1).copy(alpha = 0.1f),
                        shape = RoundedCornerShape(16.dp),
                        border = BorderStroke(1.dp, Color(0xFFF48FB1).copy(alpha = 0.3f))
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .background(Color(0xFFF48FB1), CircleShape)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "AUTOPILOT CORE ACTIVE",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFFF48FB1),
                                letterSpacing = 1.sp
                            )
                        }
                    }

                    // DNS Shield Badge
                    Surface(
                        color = Color(0xFF64B5F6).copy(alpha = 0.1f),
                        shape = RoundedCornerShape(16.dp),
                        border = BorderStroke(1.dp, Color(0xFF64B5F6).copy(alpha = 0.3f))
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = androidx.compose.material.icons.Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = Color(0xFF64B5F6),
                                modifier = Modifier.size(10.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            val dnsText = if (BypassConfig.isPanicMode) "EMERGENCY DNS" else "DNS DUAL-SHIELD"
                            Text(
                                text = dnsText,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF64B5F6),
                                letterSpacing = 1.sp
                            )
                        }
                    }

                    // Network MTU Badge
                    val currentMtu by BypassConfig.currentMtu.collectAsState()
                    Surface(
                        color = Color(0xFF81C784).copy(alpha = 0.1f),
                        shape = RoundedCornerShape(16.dp),
                        border = BorderStroke(1.dp, Color(0xFF81C784).copy(alpha = 0.3f))
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "MTU $currentMtu",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF81C784),
                                letterSpacing = 1.sp
                            )
                        }
                    }
                }

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 24.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "$connectivityScore%",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = when {
                                connectivityScore > 80 -> Color(0xFF81C784)
                                connectivityScore > 40 -> Color(0xFFFFB74D)
                                else -> Color(0xFFE57373)
                            }
                        )
                        Text(
                            text = stringResource(R.string.label_health),
                            fontSize = 10.sp,
                            color = Color(0xFFF8BBD0).copy(alpha = 0.5f),
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        val successRate by ProxyStats.successRate.collectAsStateWithLifecycle(initialValue = 100)
                        Text(
                            text = "$successRate%",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = when {
                                successRate > 80 -> Color(0xFF81C784)
                                successRate > 40 -> Color(0xFFFFB74D)
                                else -> Color(0xFFE57373)
                            }
                        )
                        Text(
                            text = stringResource(R.string.label_bypass_quality),
                            fontSize = 10.sp,
                            color = Color(0xFFF8BBD0).copy(alpha = 0.5f),
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "${ProxyStats.formatBytes(speedBytes)}/s",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFFF8BBD0)
                        )
                        Text(
                            text = ProxyStats.formatBytes(bytesTransferred),
                            fontSize = 10.sp,
                            color = Color(0xFFF8BBD0).copy(alpha = 0.8f),
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "$activeConnections",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFFF8BBD0)
                        )
                        Text(
                            text = "CONNS",
                            fontSize = 10.sp,
                            color = Color(0xFFF8BBD0).copy(alpha = 0.5f),
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = errorCount.toString(),
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (errorCount > 0) Color(0xFFE57373) else Color(0xFFF8BBD0)
                        )
                        Text(
                            text = stringResource(R.string.label_errors),
                            fontSize = 10.sp,
                            color = Color(0xFFF8BBD0).copy(alpha = 0.5f),
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = "$censorshipIntensity%",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = when {
                                censorshipIntensity > 60 -> Color(0xFFE57373)
                                censorshipIntensity > 20 -> Color(0xFFFFB74D)
                                else -> Color(0xFFF8BBD0)
                            }
                        )
                        Text(
                            text = "DPI BLOCK",
                            fontSize = 10.sp,
                            color = Color(0xFFF8BBD0).copy(alpha = 0.5f),
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
                
                // Speed Graph
                if (speedHistory.size > 1) {
                    Canvas(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp)
                            .padding(horizontal = 16.dp, vertical = 8.dp)
                    ) {
                        val maxSpeed = speedHistory.maxOrNull()?.coerceAtLeast(1024L) ?: 1024L
                        val path = Path()
                        val widthPerPoint = size.width / (speedHistory.size - 1).coerceAtLeast(1)
                        
                        // Draw line with smooth cubic bezier curves
                        val firstY = size.height - (speedHistory.firstOrNull() ?: 0L) / maxSpeed.toFloat() * size.height
                        path.moveTo(0f, firstY)
                        
                        for (i in 0 until speedHistory.size - 1) {
                            val x1 = i * widthPerPoint
                            val y1 = size.height - (speedHistory[i] / maxSpeed.toFloat() * size.height)
                            val x2 = (i + 1) * widthPerPoint
                            val y2 = size.height - (speedHistory[i + 1] / maxSpeed.toFloat() * size.height)
                            
                            val cx = (x1 + x2) / 2f
                            path.cubicTo(cx, y1, cx, y2, x2, y2)
                        }
                        
                        drawPath(
                            path = path,
                            color = Color(0xFFF48FB1),
                            style = Stroke(width = 2.dp.toPx())
                        )
                        
                        // Draw fill gradient
                        path.lineTo(size.width, size.height)
                        path.lineTo(0f, size.height)
                        path.close()
                        drawPath(
                            path = path,
                            brush = Brush.verticalGradient(
                                colors = listOf(Color(0xFFF48FB1).copy(alpha = 0.4f), Color.Transparent)
                            )
                        )
                    }
                }
            } else {
                Spacer(modifier = Modifier.height(86.dp))
            }
            
                // Core Engine Diagnostics
                if (isActive) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 24.dp)
                            .clip(RoundedCornerShape(16.dp))
                            .background(Color.Black.copy(alpha = 0.3f))
                            .border(1.dp, Color(0xFFF48FB1).copy(alpha = 0.1f), RoundedCornerShape(16.dp))
                            .padding(16.dp)
                    ) {
                        Text(
                            text = "CORE ENGINE DIAGNOSTICS",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFFF48FB1).copy(alpha = 0.8f),
                            letterSpacing = 1.sp,
                            modifier = Modifier.padding(bottom = 12.dp)
                        )
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("MEMORY POOL", fontSize = 9.sp, color = Color.White.copy(alpha = 0.5f))
                                Text("8K: $pool8kSize/64 | 16K: $pool16kSize/32", fontSize = 11.sp, color = Color.White, fontWeight = FontWeight.Bold)
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text("SCHEDULER", fontSize = 9.sp, color = Color.White.copy(alpha = 0.5f))
                                val schedulerLoad = (activeConnections * 5).coerceIn(0, 100)
                                Text("$schedulerLoad% LOAD", fontSize = 11.sp, color = if (schedulerLoad > 80) Color(0xFFE57373) else Color(0xFF81C784), fontWeight = FontWeight.Bold)
                            }
                        }
                        
                        Spacer(modifier = Modifier.height(12.dp))
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("TRAFFIC PACER", fontSize = 9.sp, color = Color.White.copy(alpha = 0.5f))
                                val pacerStatus = if (currentRttMs > 300) "CONGESTED" else "OPTIMAL"
                                Text(pacerStatus, fontSize = 11.sp, color = if (pacerStatus == "OPTIMAL") Color(0xFF81C784) else Color(0xFFFFB74D), fontWeight = FontWeight.Bold)
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text("CONGESTION WINDOW", fontSize = 9.sp, color = Color.White.copy(alpha = 0.5f))
                                Text("$congestionWindow PACKETS", fontSize = 11.sp, color = Color(0xFF81C784), fontWeight = FontWeight.Bold)
                            }
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("ROBUST RESOLVER", fontSize = 9.sp, color = Color.White.copy(alpha = 0.5f))
                                Text("S: $dnsSuccess | F: $dnsFailure", fontSize = 11.sp, color = Color.White, fontWeight = FontWeight.Bold)
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text("DNS CACHE", fontSize = 9.sp, color = Color.White.copy(alpha = 0.5f))
                                Text("${RobustResolver.dnsCacheSize} ENTRIES", fontSize = 11.sp, color = Color(0xFF81C784), fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }

                val buttonColor by animateColorAsState(
                targetValue = if (isActive) Color(0xFFB0124D) else Color(0xFFF8BBD0).copy(alpha = 0.05f),
                animationSpec = tween(500), label = "btnColor"
            )
            
            val pulseScale by infiniteTransition.animateFloat(
                initialValue = 1f,
                targetValue = if (isActive) 1.15f else 1f,
                animationSpec = infiniteRepeatable(
                    animation = tween(1500, easing = LinearEasing),
                    repeatMode = RepeatMode.Reverse
                ), label = "pulse"
            )
            
            val pulseAlpha by infiniteTransition.animateFloat(
                initialValue = 0.5f,
                targetValue = if (isActive) 0f else 0f,
                animationSpec = infiniteRepeatable(
                    animation = tween(1500, easing = LinearEasing),
                    repeatMode = RepeatMode.Restart
                ), label = "pulseAlpha"
            )
            
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(160.dp)
            ) {
                if (isActive) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .scale(pulseScale)
                            .clip(CircleShape)
                            .background(Color(0xFFB0124D).copy(alpha = pulseAlpha))
                    )
                }
                
                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier
                        .size(140.dp)
                        .clip(CircleShape)
                        .background(buttonColor)
                        .clickable { onToggle() }
                        .padding(8.dp)
                ) {
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier
                            .fillMaxSize()
                            .clip(CircleShape)
                            .background(if (isActive) Color(0xFF7A0A38) else Color.Black)
                    ) {
                        Icon(
                            imageVector = Icons.Default.PowerSettingsNew,
                            contentDescription = "Power",
                            tint = if (isActive) Color(0xFFF8BBD0) else Color(0xFF880E4F),
                            modifier = Modifier.size(56.dp)
                        )
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Text(
                text = if (isActive) stringResource(R.string.label_secure_tunnel_active) else stringResource(R.string.label_system_offline),
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                color = if (isActive) Color(0xFFF8BBD0) else Color(0xFFAD1457)
            )
            
            if (isActive) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center,
                    modifier = Modifier.padding(top = 4.dp)
                ) {
                    Text(
                        text = "SESSION TIME: $formattedSessionTime",
                        fontSize = 11.sp,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFF48FB1).copy(alpha = 0.7f)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "|",
                        fontSize = 11.sp,
                        color = Color(0xFFF48FB1).copy(alpha = 0.3f)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "PROFILE: ${currentNetworkType.name}",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = Color(0xFF81C784),
                        modifier = Modifier
                            .background(Color(0xFF81C784).copy(alpha = 0.15f), RoundedCornerShape(4.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "RTT: ${currentRttMs}ms (x${"%.1f".format((currentRttMs.toDouble() / 50.0).coerceIn(0.5, 3.0))})",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = Color(0xFFF8BBD0),
                        modifier = Modifier
                            .background(Color(0xFFF8BBD0).copy(alpha = 0.15f), RoundedCornerShape(4.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            if (isActive && recoveryLog.isNotEmpty()) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.label_autopilot_actions),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFF8BBD0).copy(alpha = 0.4f),
                        letterSpacing = 1.sp
                    )
                    val youtubeDown = serviceStatuses.any { it.name == "YouTube" && !it.isUp }
                    val isOptimizing = !isProxyHealthy || youtubeDown
                    
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "FLUSH DNS",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFFF8BBD0),
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .background(Color(0xFFF8BBD0).copy(alpha = 0.1f))
                                .clickable { 
                                    RobustResolver.clearCache()
                                    ProxyStats.logRecovery("DNS Cache Flushed Manually")
                                }
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = if (isOptimizing) stringResource(R.string.action_force_reoptimize) else stringResource(R.string.action_optimize),
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (isOptimizing) Color(0xFFF8BBD0) else Color(0xFFF48FB1),
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .background(if (isOptimizing) Color(0xFFD81B60) else Color(0xFFF48FB1).copy(alpha = 0.1f))
                                .clickable { 
                                    val intent = Intent(context, PinkVpnService::class.java).apply {
                                        action = "RESTART"
                                    }
                                    context.startService(intent)
                                }
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                }
                val youtubeStatus = serviceStatuses.find { it.name == "YouTube" }
                val blockDetected = youtubeStatus != null && !youtubeStatus.isUp && serviceStatuses.any { it.name.contains("Control") && it.isUp }
                
                // Advanced Strategy Display
                Box {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp)
                            .background(Color(0xFF111111), RoundedCornerShape(12.dp))
                            .border(1.dp, Color(0xFFF48FB1).copy(alpha = 0.2f), RoundedCornerShape(12.dp))
                            .clickable { showStrategyMenu = true }
                            .padding(12.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text(
                                    text = "ACTIVE DPI EVASION ▾",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFFF48FB1),
                                    letterSpacing = 1.sp
                                )
                                Text(
                                    text = activeStrategy.name.replace("_", " "),
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    color = Color(0xFFF8BBD0)
                                )
                            }
                            if (blockDetected) {
                                Row(
                                    modifier = Modifier
                                        .background(Color(0xFFE57373).copy(alpha = 0.2f), RoundedCornerShape(4.dp))
                                        .padding(horizontal = 6.dp, vertical = 2.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(Icons.Default.Warning, contentDescription = null, tint = Color(0xFFE57373), modifier = Modifier.size(10.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        text = "BLOCK DETECTED",
                                        fontSize = 8.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFFE57373)
                                    )
                                }
                            } else {
                                Row(
                                    modifier = Modifier
                                        .background(Color(0xFF81C784).copy(alpha = 0.2f), RoundedCornerShape(4.dp))
                                        .padding(horizontal = 6.dp, vertical = 2.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(Icons.Default.CheckCircle, contentDescription = null, tint = Color(0xFF81C784), modifier = Modifier.size(10.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        text = "BYPASS ACTIVE",
                                        fontSize = 8.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color(0xFF81C784)
                                    )
                                }
                            }
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "FRAG (Dyn/Base): $currentFragSize / ${BypassConfig.frag1} | DELAY: ${BypassConfig.delay1}ms | TTL: ${BypassConfig.fakeTtl}",
                            fontSize = 9.sp,
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                            color = Color(0xFF81C784),
                            modifier = Modifier.padding(bottom = 8.dp)
                        )
                        Text(
                            text = when (activeStrategy.name) {
                                "TCP_OOB_DESYNC" -> "Injects Out-of-Band (Urgent) TCP data to desynchronize DPI state while the target server discards the garbage."
                                "TCP_DESYNC_FAKE" -> "Sends a fake ClientHello with reduced IP TTL. The DPI analyzes the fake packet, but routers drop it before it reaches the server."
                                "TLS_PAD" -> "Pads the TLS ClientHello with a large padding extension to exceed 1500 bytes, forcing TCP fragmentation and confusing DPI length analysis."
                                "TLS_GREASE" -> "Injects randomized GREASE extensions and shuffles extensions order to scramble JA3/JA4 fingerprints."
                                "SNI_FAKE" -> "Performs a double split by sending a complete fake TLS handshake header followed by the real one, confusing deep packet inspection."
                                "HTTP_SPACE" -> "Injects horizontal tabs and spaces into HTTP methods to evade regex-based filters on transparent proxies."
                                "SNI_TRIPLE" -> "Divides the TLS Server Name Indication (SNI) into three fragmented chunks, bypassing DPI substring matching."
                                "TLS_DIRTY", "JUNK_PADDING" -> "Pads the TLS header with random byte garbage that gets ignored by the server but crashes DPI parsers."
                                else -> "Applies advanced payload fragmentation and byte-level manipulation to evade Deep Packet Inspection systems."
                            },
                            fontSize = 11.sp,
                            color = Color(0xFFF8BBD0).copy(alpha = 0.6f),
                            lineHeight = 14.sp
                        )
                    }
                    
                    DropdownMenu(
                        expanded = showStrategyMenu,
                        onDismissRequest = { showStrategyMenu = false },
                        modifier = Modifier.background(Color(0xFF111111)).heightIn(max = 300.dp)
                    ) {
                        BypassStrategy.entries.forEach { strategy ->
                            val score = BypassConfig.getStrategyScore(strategy)
                            DropdownMenuItem(
                                text = { 
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(strategy.name.replace("_", " "), color = Color(0xFFF8BBD0), fontSize = 12.sp)
                                        Spacer(modifier = Modifier.width(16.dp))
                                        Text(
                                            text = "$score pts", 
                                            color = when {
                                                score > 400 -> Color(0xFF81C784)
                                                score > 200 -> Color(0xFFFFB74D)
                                                else -> Color(0xFFE57373)
                                            },
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                },
                                onClick = {
                                    showStrategyMenu = false
                                    BypassConfig.setStrategy(strategy)
                                    val intent = Intent(context, PinkVpnService::class.java).apply {
                                        action = "CHANGE_STRATEGY"
                                    }
                                    context.startService(intent)
                                }
                            )
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(8.dp))

                // Network Status Intelligence Card
                Card(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFFF8BBD0).copy(alpha = 0.05f)),
                    shape = RoundedCornerShape(12.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Color(0xFFF48FB1).copy(alpha = 0.1f))
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("NETWORK INTELLIGENCE", fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF48FB1), letterSpacing = 1.sp)
                            Spacer(modifier = Modifier.height(4.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("DNS: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                val dnsStatusText = when (RobustResolver.dnsMode) {
                                    "Smart DoH" -> "PROTECTED (DoH)"
                                    "Custom" -> "CUSTOM DNS"
                                    else -> "STANDARD"
                                }
                                val dnsStatusColor = when (RobustResolver.dnsMode) {
                                    "Smart DoH" -> Color(0xFF81C784)
                                    "Custom" -> Color(0xFFF48FB1)
                                    else -> Color(0xFFFFB74D)
                                }
                                Text(dnsStatusText, fontSize = 11.sp, color = dnsStatusColor, fontWeight = FontWeight.Bold)
                            }
                            if (RobustResolver.dnsMode == "Smart DoH") {
                                val bestDns = RobustResolver.getBestProviderAndLatency()
                                if (bestDns != null) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text("  ↳ Active Server: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.5f))
                                        Text("${bestDns.first} (${bestDns.second}ms)", fontSize = 11.sp, color = Color(0xFF81C784), fontWeight = FontWeight.SemiBold)
                                    }
                                }
                            } else if (RobustResolver.dnsMode == "Custom") {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text("  ↳ Target: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.5f))
                                    Text(RobustResolver.customDnsIp, fontSize = 11.sp, color = Color(0xFFF48FB1), fontWeight = FontWeight.SemiBold)
                                }
                            }
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.clickable {
                                    BypassConfig.blockQuic = !BypassConfig.blockQuic
                                    BypassConfig.saveTuningSettings(context)
                                }.padding(vertical = 2.dp)
                            ) {
                                Text("QUIC (UDP 443): ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text(if (BypassConfig.blockQuic) "BLOCKED (Tap to allow)" else "ALLOWED (Tap to block)", fontSize = 11.sp, color = if (BypassConfig.blockQuic) Color(0xFF81C784) else Color(0xFFFFB74D), fontWeight = FontWeight.Bold)
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("TCP Kernel: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text("FAST_OPEN + NODELAY", fontSize = 11.sp, color = Color(0xFF81C784), fontWeight = FontWeight.Bold)
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("Bypass Efficiency: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                val successRate = ProxyStats.getSuccessRate()
                                Text("$successRate%", fontSize = 11.sp, color = if (successRate > 80) Color(0xFF81C784) else if (successRate > 50) Color(0xFFFFB74D) else Color(0xFFE57373), fontWeight = FontWeight.Bold)
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("Censorship Level: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                val cLevelStr = when {
                                    censorshipIntensity < 25 -> "LOW ($censorshipIntensity%)"
                                    censorshipIntensity < 65 -> "MEDIUM ($censorshipIntensity%)"
                                    else -> "HIGH ($censorshipIntensity%)"
                                }
                                val cLevelColor = when {
                                    censorshipIntensity < 25 -> Color(0xFF81C784)
                                    censorshipIntensity < 65 -> Color(0xFFFFB74D)
                                    else -> Color(0xFFE57373)
                                }
                                Text(cLevelStr, fontSize = 11.sp, color = cLevelColor, fontWeight = FontWeight.Bold)
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("Signal Quality: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text("$signalQuality%", fontSize = 11.sp, color = if (signalQuality > 75) Color(0xFF81C784) else if (signalQuality > 40) Color(0xFFFFB74D) else Color(0xFFE57373), fontWeight = FontWeight.Bold)
                            }
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.clickable {
                                    BypassConfig.isAutoTuning = !BypassConfig.isAutoTuning
                                    BypassConfig.saveTuningSettings(context)
                                }.padding(vertical = 2.dp)
                            ) {
                                Text("Auto-Tuning: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text(if (BypassConfig.isAutoTuning) "ACTIVE (Tap to disable)" else "MANUAL (Tap to enable)", fontSize = 11.sp, color = if (BypassConfig.isAutoTuning) Color(0xFF81C784) else Color(0xFFFFB74D), fontWeight = FontWeight.Bold)
                            }
                            
                            val cwnd by ProxyStats.congestionWindow.collectAsStateWithLifecycle(initialValue = 10)
                            val poolSize by ProxyStats.pool16kSize.collectAsStateWithLifecycle(initialValue = 0)
                            
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 2.dp)) {
                                Text("Congestion Window: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text("${cwnd} pkts/burst", fontSize = 11.sp, color = Color(0xFFBA68C8), fontWeight = FontWeight.Bold)
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("Buffer Pool (16K): ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text("$poolSize chunks", fontSize = 11.sp, color = Color(0xFF4FC3F7), fontWeight = FontWeight.Bold)
                            }
                            
                            val isPanic by BypassConfig.isPanicModeFlow.collectAsStateWithLifecycle(initialValue = BypassConfig.isPanicMode)
                            val mtu by BypassConfig.currentMtu.collectAsStateWithLifecycle()
                            
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 2.dp)) {
                                Text("Network MTU: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text("$mtu bytes", fontSize = 11.sp, color = Color(0xFF81C784), fontWeight = FontWeight.Bold)
                            }
                            if (isPanic) {
                                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 2.dp)) {
                                    Text("Status: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                    Text("PANIC MODE", fontSize = 11.sp, color = Color(0xFFE57373), fontWeight = FontWeight.ExtraBold)
                                }
                            }
                        }
                        Column(horizontalAlignment = Alignment.End) {
                            val rttMs by BypassConfig.currentRttMs.collectAsStateWithLifecycle(initialValue = 50L)
                            Text("RTT", fontSize = 9.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF8BBD0).copy(alpha = 0.4f), letterSpacing = 1.sp)
                            Text("${rttMs}ms", fontSize = 16.sp, fontWeight = FontWeight.ExtraBold, color = Color(0xFFF8BBD0))
                            Spacer(modifier = Modifier.height(4.dp))
                            Box(
                                modifier = Modifier
                                    .background(
                                        if (isProbing) Color(0xFFE57373).copy(alpha = 0.2f) else Color(0xFF81C784).copy(alpha = 0.2f),
                                        shape = RoundedCornerShape(4.dp)
                                    )
                                    .clickable(enabled = !isProbing) {
                                        ServiceChecker.runActiveProbing(context)
                                    }
                                    .padding(horizontal = 6.dp, vertical = 3.dp)
                            ) {
                                Text(
                                    text = if (isProbing) "PROBING..." else "RUN TOURNAMENT",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (isProbing) Color(0xFFE57373) else Color(0xFF81C784)
                                )
                            }
                        }
                    }
                }

                val logsScrollState = rememberScrollState()
                val trafficScrollState = rememberScrollState()
                
                LaunchedEffect(recoveryLog.size) {
                    if (recoveryLog.isNotEmpty()) {
                        logsScrollState.animateScrollTo(logsScrollState.maxValue)
                    }
                }

                LaunchedEffect(trafficLog.size) {
                    if (trafficLog.isNotEmpty()) {
                        trafficScrollState.animateScrollTo(trafficScrollState.maxValue)
                    }
                }

                val logListState = androidx.compose.foundation.lazy.rememberLazyListState()
                androidx.compose.foundation.lazy.LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 120.dp)
                        .background(Color.Black.copy(alpha = 0.3f), RoundedCornerShape(8.dp))
                        .padding(8.dp),
                    state = logListState
                ) {
                    items(recoveryLog) { log ->
                        Text(
                            text = log,
                            color = if (log.contains("Healing") || log.contains("Optimizing")) Color(0xFFF06292) else Color(0xFFF48FB1).copy(alpha = 0.6f),
                            fontSize = 9.sp,
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                            modifier = Modifier.padding(vertical = 1.dp)
                        )
                    }
                }
                
                // Auto-scroll effect for LazyColumn
                LaunchedEffect(recoveryLog.size) {
                    if (recoveryLog.isNotEmpty()) {
                        logListState.animateScrollToItem(0) // Since we prepended new logs
                    }
                }
                
                Spacer(modifier = Modifier.height(12.dp))
                
                // Traffic Speed Graph
                val speedHistory by ProxyStats.speedHistory.collectAsStateWithLifecycle()
                if (speedHistory.isNotEmpty()) {
                    androidx.compose.foundation.Canvas(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(40.dp)
                            .padding(bottom = 8.dp)
                    ) {
                        val maxSpeed = speedHistory.maxOrNull()?.coerceAtLeast(1024L) ?: 1024L
                        val stepX = size.width / (speedHistory.size.coerceAtLeast(2) - 1).coerceAtLeast(1)
                        val path = androidx.compose.ui.graphics.Path()
                        speedHistory.forEachIndexed { index, speed ->
                            val x = index * stepX
                            val y = size.height - (speed.toFloat() / maxSpeed * size.height).coerceIn(0f, size.height)
                            if (index == 0) path.moveTo(x, y) else path.lineTo(x, y)
                        }
                        drawPath(path, color = Color(0xFFF48FB1), style = androidx.compose.ui.graphics.drawscope.Stroke(width = 2.dp.toPx()))
                    }
                }

                Text(
                    text = "LIVE TRAFFIC",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFF8BBD0).copy(alpha = 0.4f),
                    letterSpacing = 1.sp,
                    modifier = Modifier.align(Alignment.Start).padding(bottom = 8.dp)
                )
                
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 100.dp)
                        .background(Color.Black.copy(alpha = 0.3f), RoundedCornerShape(8.dp))
                        .verticalScroll(trafficScrollState)
                        .padding(8.dp)
                ) {
                    trafficLog.forEach { log ->
                        Text(
                            text = log,
                            color = Color(0xFF81C784).copy(alpha = 0.8f),
                            fontSize = 9.sp,
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                            modifier = Modifier.padding(vertical = 1.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
                
                if (topHosts.isNotEmpty()) {
                    Text(
                        "TOP DOMAINS",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFF48FB1),
                        letterSpacing = 1.sp,
                        modifier = Modifier.align(Alignment.Start).padding(bottom = 8.dp)
                    )
                    
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color.Black.copy(alpha = 0.3f), RoundedCornerShape(8.dp))
                            .padding(8.dp)
                    ) {
                        topHosts.forEach { (host, count) ->
                            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text(text = host, color = Color(0xFFF8BBD0), fontSize = 10.sp, maxLines = 1, modifier = Modifier.weight(1f))
                                val strategyName = BypassConfig.resolveSessionConfigForHost(host).strategy.name
                                Text(text = "$count REQ • $strategyName", color = Color(0xFFF48FB1), fontSize = 10.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                }
            }

            if (isActive && serviceStatuses.isNotEmpty()) {
                Spacer(modifier = Modifier.height(24.dp))
                
                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.label_service_monitor),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFF8BBD0).copy(alpha = 0.4f),
                        letterSpacing = 1.sp
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (lastCheckTime > 0) {
                            Text(
                                text = stringResource(R.string.label_updated, SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(lastCheckTime))),
                                fontSize = 9.sp,
                                color = Color(0xFFF8BBD0).copy(alpha = 0.3f),
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(end = 8.dp)
                            )
                        }
                        IconButton(
                            onClick = { ServiceChecker.triggerCheck() },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Refresh,
                                contentDescription = "Refresh",
                                tint = Color(0xFFF8BBD0).copy(alpha = 0.5f),
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                }

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color(0xFFF8BBD0).copy(alpha = 0.03f), RoundedCornerShape(16.dp))
                        .padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    serviceStatuses.forEach { status ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color(0xFFF8BBD0).copy(alpha = 0.02f), RoundedCornerShape(8.dp))
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column {
                                Text(
                                    text = status.name,
                                    color = Color(0xFFF8BBD0),
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = status.url.removePrefix("https://").removePrefix("www."),
                                    color = Color(0xFFF8BBD0).copy(alpha = 0.3f),
                                    fontSize = 10.sp
                                )
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                if (status.isUp && status.latencyMs > 0) {
                                    Text(
                                        text = "${status.latencyMs} ms",
                                        color = if (status.latencyMs < 300) Color(0xFF81C784) else Color(0xFFFFB74D),
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(end = 8.dp)
                                    )
                                }
                                Icon(
                                    imageVector = if (status.isUp) Icons.Default.CheckCircle else Icons.Default.Cancel,
                                    contentDescription = null,
                                    tint = if (status.isUp) Color(0xFF81C784) else Color(0xFFE57373),
                                    modifier = Modifier.size(14.dp)
                                )
                            }
                        }
                    }
                }
                Spacer(modifier = Modifier.height(24.dp))
            } else {
                Spacer(modifier = Modifier.height(32.dp))
            }

            // New Automation Cards
            AutoConnectCard(context = context)
            
            val pm = context.getSystemService(android.os.PowerManager::class.java)
            val isIgnoringBattery = pm?.isIgnoringBatteryOptimizations(context.packageName) == true
            if (!isIgnoringBattery) {
                BatteryOptimizationInfoCard(context = context)
            }

            AppFilterCard(context = context, onSettingsChanged = onRestart)

            ExpertSettingsCard(context = context, isVpnActive = isActive)

            // Connection Instructions Card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 16.dp)
                    .border(1.dp, Color(0xFFF48FB1).copy(alpha = 0.3f), RoundedCornerShape(16.dp)),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF111111).copy(alpha = 0.8f)
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp)
                ) {
                    Text(
                        text = "💡 ИНСТРУКЦИЯ / CONNECTION GUIDE",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = Color(0xFFF48FB1),
                        modifier = Modifier.padding(bottom = 8.dp)
                    )
                    Text(
                        text = "• Системный обход:\n" +
                               "  Приложение запускает VPN и настраивает системный HTTP прокси (127.0.0.1:18080) автоматически. " +
                               "Браузеры (Chrome, Yandex, Kiwi) используют его по умолчанию — открывайте YouTube в браузере для 100% стабильного обхода.\n\n" +
                               "• Поддержка Telegram & SOCKS5:\n" +
                               "  Мы добавили встроенный SOCKS5 прокси на порту 18080. " +
                               "В настройках Telegram перейдите в Данные и память -> Прокси и добавьте SOCKS5 прокси:\n" +
                               "  - Хост: 127.0.0.1\n" +
                               "  - Порт: 18080\n" +
                               "  Это перенаправит Telegram напрямую через наши DPI-обходные стратегии!\n\n" +
                               "• Официальные приложения (YouTube, etc):\n" +
                               "  Некоторые приложения полностью игнорируют системный прокси. Если видео в приложении YouTube не грузятся, используйте веб-версию в Chrome или Yandex Browser.",
                        fontSize = 11.sp,
                        color = Color(0xFFF8BBD0).copy(alpha = 0.8f),
                        lineHeight = 16.sp
                    )
                }
            }
        }
    }
}

@Composable
fun AutoConnectCard(context: android.content.Context) {
    val prefs = context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
    var autoConnect by remember { mutableStateOf(prefs.getBoolean("auto_connect_on_launch", true)) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .border(1.dp, Color(0xFFF48FB1).copy(alpha = 0.2f), RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Black.copy(alpha = 0.5f)
        )
    ) {
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
                    color = Color(0xFFF8BBD0)
                )
                Text(
                    text = stringResource(R.string.desc_auto_connect),
                    fontSize = 11.sp,
                    color = Color(0xFFF8BBD0).copy(alpha = 0.6f),
                    lineHeight = 14.sp
                )
            }
            Switch(
                checked = autoConnect,
                onCheckedChange = {
                    autoConnect = it
                    prefs.edit().putBoolean("auto_connect_on_launch", it).apply()
                },
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color(0xFFF48FB1),
                    checkedTrackColor = Color(0xFFD81B60)
                )
            )
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
                color = Color(0xFFF8BBD0).copy(alpha = 0.8f),
                lineHeight = 15.sp
            )
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = {
                    try {
                        val intent = Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                            data = android.net.Uri.parse("package:${context.packageName}")
                        }
                        context.startActivity(intent)
                    } catch (e: Exception) {
                        try {
                            val intent = Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                data = android.net.Uri.parse("package:${context.packageName}")
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
                Text(stringResource(R.string.action_disable), fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF8BBD0))
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
            .border(1.dp, Color(0xFFF8BBD0).copy(alpha = 0.2f), RoundedCornerShape(16.dp)),
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
                        color = Color(0xFFF8BBD0)
                    )
                    Text(
                        text = stringResource(R.string.desc_app_filter),
                        fontSize = 11.sp,
                        color = Color(0xFFF8BBD0).copy(alpha = 0.6f),
                        lineHeight = 14.sp
                    )
                }
                Icon(
                    imageVector = Icons.Default.FilterList,
                    contentDescription = null,
                    tint = Color(0xFFF8BBD0),
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
                    color = Color(0xFFF8BBD0),
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
                        checkedThumbColor = Color(0xFFF8BBD0),
                        checkedTrackColor = Color(0xFFD81B60)
                    )
                )
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            Button(
                onClick = { showDialog = true },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFD81B60)),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth().height(40.dp)
            ) {
                Text(
                    text = "${stringResource(R.string.action_select_apps)} ($selectedCount)",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFF8BBD0)
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
        val drawable = withContext(Dispatchers.IO) {
            try {
                context.packageManager.getApplicationIcon(appInfo)
            } catch (e: Exception) {
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
                .background(Color(0xFFF8BBD0).copy(alpha = 0.1f), RoundedCornerShape(8.dp)),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = label.take(1).uppercase(),
                color = Color(0xFFF8BBD0),
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
        withContext(Dispatchers.IO) {
            val installedApps = pm.getInstalledApplications(android.content.pm.PackageManager.GET_META_DATA)
                .filter { (it.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0 || it.packageName == "com.google.android.youtube" || it.packageName == "org.telegram.messenger" }
                .map { app ->
                    val label = app.loadLabel(pm).toString()
                    AppEntry(app, label, app.packageName)
                }
                .sortedBy { it.label }
            apps = installedApps
            isLoading = false
        }
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
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = Color(0xFFF8BBD0))
                    }
                    Text(
                        stringResource(R.string.action_select_apps),
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFF8BBD0)
                    )
                }

                // Search
                TextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                    placeholder = { Text("Search apps...", color = Color(0xFFF8BBD0).copy(alpha = 0.5f)) },
                    colors = TextFieldDefaults.colors(
                        focusedContainerColor = Color(0xFFF8BBD0).copy(alpha = 0.05f),
                        unfocusedContainerColor = Color(0xFFF8BBD0).copy(alpha = 0.05f),
                        focusedIndicatorColor = Color(0xFFF48FB1),
                        unfocusedIndicatorColor = Color.Transparent,
                        cursorColor = Color(0xFFF48FB1),
                        focusedTextColor = Color(0xFFF8BBD0),
                        unfocusedTextColor = Color(0xFFF8BBD0)
                    ),
                    shape = RoundedCornerShape(12.dp)
                )

                if (isLoading) {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = Color(0xFFF48FB1))
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
                                        color = Color(0xFFF8BBD0),
                                        fontSize = 15.sp,
                                        fontWeight = FontWeight.Medium
                                    )
                                    Text(
                                        text = pkg,
                                        color = Color(0xFFF8BBD0).copy(alpha = 0.5f),
                                        fontSize = 12.sp
                                    )
                                }
                                
                                Checkbox(
                                    checked = isSelected,
                                    onCheckedChange = null, // Handled by row click
                                    colors = CheckboxDefaults.colors(
                                        checkedColor = Color(0xFFF48FB1),
                                        uncheckedColor = Color(0xFFF8BBD0).copy(alpha = 0.3f)
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
    var autoConnect by remember { mutableStateOf(context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE).getBoolean("auto_connect_on_launch", true)) }

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
            ServiceChecker.loadCustomServices(context)
        }
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .border(1.dp, Color(0xFFF48FB1).copy(alpha = 0.3f), RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF111111).copy(alpha = 0.8f)
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
                        tint = Color(0xFFF48FB1),
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "🛠️ ИНЖЕНЕРНАЯ ПАНЕЛЬ / EXPERT TUNING",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = Color(0xFFF48FB1)
                    )
                }
                Icon(
                    imageVector = if (expanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                    contentDescription = null,
                    tint = Color(0xFFF48FB1).copy(alpha = 0.7f)
                )
            }

            if (expanded) {
                HorizontalDivider(
                    color = Color(0xFFF48FB1).copy(alpha = 0.2f),
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
                            color = Color(0xFFF8BBD0)
                        )
                        Text(
                            text = "Автоматический запуск при открытии приложения",
                            fontSize = 9.sp,
                            color = Color(0xFFF8BBD0).copy(alpha = 0.4f)
                        )
                    }
                    Switch(
                        checked = autoConnect,
                        onCheckedChange = { 
                            autoConnect = it
                            context.getSharedPreferences("pink_proxy_settings", android.content.Context.MODE_PRIVATE)
                                .edit().putBoolean("auto_connect_on_launch", it).apply()
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color(0xFFF48FB1),
                            checkedTrackColor = Color(0xFFF48FB1).copy(alpha = 0.5f)
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
                            color = Color(0xFFF8BBD0)
                        )
                        Text(
                            text = "Автоматическая подстройка DPI",
                            fontSize = 9.sp,
                            color = Color(0xFFF8BBD0).copy(alpha = 0.4f)
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
                            checkedThumbColor = Color(0xFFF48FB1),
                            checkedTrackColor = Color(0xFFF48FB1).copy(alpha = 0.5f)
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
                            color = Color(0xFFF8BBD0)
                        )
                        Text(
                            text = "Блокировка QUIC (IPv6). Для IPv4 рекомендуется отключить QUIC в браузере (chrome://flags)",
                            fontSize = 9.sp,
                            color = Color(0xFFF8BBD0).copy(alpha = 0.5f)
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
                            checkedThumbColor = Color(0xFFF48FB1),
                            checkedTrackColor = Color(0xFFF48FB1).copy(alpha = 0.5f)
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
                    color = Color(0xFFF48FB1).copy(alpha = 0.15f),
                    thickness = 1.dp,
                    modifier = Modifier.padding(bottom = 12.dp)
                )

                // 1. DNS Settings Section
                Text(
                    text = "1. НАСТРОЙКИ SECURE DNS (DoH)",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFF8BBD0).copy(alpha = 0.9f),
                    modifier = Modifier.padding(bottom = 6.dp)
                )

                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    val smartBg = if (dnsMode == "Smart DoH") Color(0xFFD81B60) else Color(0xFFF48FB1).copy(alpha = 0.1f)
                    val customBg = if (dnsMode == "Custom") Color(0xFFD81B60) else Color(0xFFF48FB1).copy(alpha = 0.1f)

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
                        Text("Smart DoH", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF8BBD0))
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
                        Text("Custom DNS/DoH", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF8BBD0))
                    }
                }

                if (dnsMode == "Custom") {
                    OutlinedTextField(
                        value = customDnsIp,
                        onValueChange = {
                            customDnsIp = it
                            RobustResolver.saveDnsSettings(context, "Custom", it)
                        },
                        label = { Text("DNS IP (e.g. 9.9.9.9) or DoH URL", color = Color(0xFFF48FB1).copy(alpha = 0.5f), fontSize = 11.sp) },
                        textStyle = androidx.compose.ui.text.TextStyle(color = Color(0xFFF8BBD0), fontSize = 12.sp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Color(0xFFF48FB1),
                            unfocusedBorderColor = Color(0xFFF48FB1).copy(alpha = 0.4f),
                            cursorColor = Color(0xFFF48FB1)
                        ),
                        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                        singleLine = true
                    )
                }

                HorizontalDivider(
                    color = Color(0xFFF48FB1).copy(alpha = 0.1f),
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
                        color = Color(0xFFF8BBD0).copy(alpha = 0.9f)
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "Auto-Tuning",
                            fontSize = 10.sp,
                            color = Color(0xFFF8BBD0).copy(alpha = 0.6f),
                            modifier = Modifier.padding(end = 6.dp)
                        )
                        Switch(
                            checked = isAutoTuning,
                            onCheckedChange = {
                                isAutoTuning = it
                                BypassConfig.isAutoTuning = it
                                BypassConfig.saveTuningSettings(context)
                                if (it) {
                                    // Trigger immediate re-mutation
                                    val intent = Intent(context, PinkVpnService::class.java).apply {
                                        action = "CHANGE_STRATEGY"
                                    }
                                    context.startService(intent)
                                }
                            },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = Color(0xFFF48FB1),
                                checkedTrackColor = Color(0xFFD81B60),
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
                        color = Color(0xFFF8BBD0).copy(alpha = 0.5f),
                        lineHeight = 14.sp,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )

                    // Param Sliders
                    // 1. frag1
                    Column(modifier = Modifier.padding(vertical = 4.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Размер 1-го фрагмента (frag1):", fontSize = 10.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.8f))
                            Text("${frag1.toInt()} байт", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF48FB1))
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
                                thumbColor = Color(0xFFF48FB1),
                                activeTrackColor = Color(0xFFD81B60)
                            )
                        )
                    }

                    // 2. frag2
                    Column(modifier = Modifier.padding(vertical = 4.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Размер 2-го фрагмента (frag2):", fontSize = 10.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.8f))
                            Text("${frag2.toInt()} байт", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF48FB1))
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
                                thumbColor = Color(0xFFF48FB1),
                                activeTrackColor = Color(0xFFD81B60)
                            )
                        )
                    }

                    // 3. delay1
                    Column(modifier = Modifier.padding(vertical = 4.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Задержка 1-го фрагмента (delay1):", fontSize = 10.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.8f))
                            Text("${delay1.toInt()} мс", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF48FB1))
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
                                thumbColor = Color(0xFFF48FB1),
                                activeTrackColor = Color(0xFFD81B60)
                            )
                        )
                    }

                    // 4. delay2
                    Column(modifier = Modifier.padding(vertical = 4.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Задержка 2-го фрагмента (delay2):", fontSize = 10.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.8f))
                            Text("${delay2.toInt()} мс", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF48FB1))
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
                                thumbColor = Color(0xFFF48FB1),
                                activeTrackColor = Color(0xFFD81B60)
                            )
                        )
                    }

                    // 5. fakeTtl
                    Column(modifier = Modifier.padding(vertical = 4.dp)) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("IP TTL для фейк-пакетов (fakeTtl):", fontSize = 10.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.8f))
                            Text("${fakeTtl.toInt()}", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF48FB1))
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
                                thumbColor = Color(0xFFF48FB1),
                                activeTrackColor = Color(0xFFD81B60)
                            )
                        )
                    }
                } else {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFFF8BBD0).copy(alpha = 0.05f), RoundedCornerShape(8.dp))
                            .padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "ℹ️ Автоматический тюнинг параметров активен. Система динамически подбирает задержки (delay: ${delay1.toInt()}/${delay2.toInt()}ms) и размеры фрагментов (frag: ${frag1.toInt()}/${frag2.toInt()}) для текущей стратегии обхода DPI.",
                            fontSize = 10.sp,
                            color = Color(0xFFF8BBD0).copy(alpha = 0.7f),
                            lineHeight = 14.sp
                        )
                    }
                }

                HorizontalDivider(
                    color = Color(0xFFF48FB1).copy(alpha = 0.1f),
                    thickness = 1.dp,
                    modifier = Modifier.padding(vertical = 12.dp)
                )

                // 3. Custom Websites Monitor
                Text(
                    text = "3. МОНИТОРИНГ СОБСТВЕННЫХ САЙТОВ",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFF8BBD0).copy(alpha = 0.9f),
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                Text(
                    text = "Добавьте сайт, который хотите разблокировать, чтобы авто-пилот отслеживал его доступность и подбирал лучшие стратегии.",
                    fontSize = 10.sp,
                    color = Color(0xFFF8BBD0).copy(alpha = 0.5f),
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
                        label = { Text("Название (e.g. Meduza)", color = Color(0xFFF48FB1).copy(alpha = 0.5f), fontSize = 10.sp) },
                        textStyle = androidx.compose.ui.text.TextStyle(color = Color(0xFFF8BBD0), fontSize = 11.sp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Color(0xFFF48FB1),
                            unfocusedBorderColor = Color(0xFFF48FB1).copy(alpha = 0.4f),
                            cursorColor = Color(0xFFF48FB1)
                        ),
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )

                    OutlinedTextField(
                        value = newServiceUrl,
                        onValueChange = { newServiceUrl = it },
                        label = { Text("https://...", color = Color(0xFFF48FB1).copy(alpha = 0.5f), fontSize = 10.sp) },
                        textStyle = androidx.compose.ui.text.TextStyle(color = Color(0xFFF8BBD0), fontSize = 11.sp),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Color(0xFFF48FB1),
                            unfocusedBorderColor = Color(0xFFF48FB1).copy(alpha = 0.4f),
                            cursorColor = Color(0xFFF48FB1)
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
                            .background(Color(0xFFD81B60), RoundedCornerShape(8.dp))
                    ) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = "Add",
                            tint = Color(0xFFF8BBD0),
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }

                if (customServices.isNotEmpty()) {
                    Text(
                        text = "Добавленные сайты (нажмите корзину для удаления):",
                        fontSize = 10.sp,
                        color = Color(0xFFF8BBD0).copy(alpha = 0.7f),
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
                                    .background(Color(0xFFF8BBD0).copy(alpha = 0.04f), RoundedCornerShape(8.dp))
                                    .padding(horizontal = 10.dp, vertical = 6.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(service.first, color = Color(0xFFF8BBD0), fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                    Text(service.second, color = Color(0xFFF8BBD0).copy(alpha = 0.4f), fontSize = 9.sp)
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
                    color = Color(0xFFF48FB1).copy(alpha = 0.1f),
                    thickness = 1.dp,
                    modifier = Modifier.padding(vertical = 12.dp)
                )

                // 4. Force Reset / Clear Scores
                Text(
                    text = "4. СБРОС И ПЕРЕЗАГРУЗКА",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFF8BBD0).copy(alpha = 0.9f),
                    modifier = Modifier.padding(bottom = 4.dp)
                )
                Text(
                    text = stringResource(R.string.desc_clear_scores),
                    fontSize = 10.sp,
                    color = Color(0xFFF8BBD0).copy(alpha = 0.5f),
                    lineHeight = 14.sp,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                Button(
                    onClick = {
                        BypassConfig.clearScores(context)
                        val intent = Intent(context, PinkVpnService::class.java).apply {
                            action = "RESTART"
                        }
                        context.startService(intent)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFC2185B)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth().height(36.dp),
                    contentPadding = PaddingValues(0.dp)
                ) {
                    Text(stringResource(R.string.action_clear_scores), fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFFF8BBD0))
                }
            }
        }
    }
}
