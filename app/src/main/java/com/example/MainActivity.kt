package com.example

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.SimpleDateFormat
import java.util.*
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.ui.theme.MyApplicationTheme
import kotlinx.coroutines.delay
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Cancel

class MainActivity : ComponentActivity() {
    private val vpnLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        enableEdgeToEdge()
        setContent {
            val isVpnActive by PinkVpnService.isRunning.collectAsStateWithLifecycle(initialValue = false)
            MyApplicationTheme(dynamicColor = false) {
                PinkProxyApp(
                    isActive = isVpnActive,
                    onToggle = { toggleVpn(isVpnActive) }
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
fun PinkProxyApp(isActive: Boolean, onToggle: () -> Unit) {
    val bgColor1 = Color(0xFF15020A) // Almost black with pink tint
    val bgColor2 = Color(0xFF2A0614) // Very dark pink/burgundy
    val bgColor3 = Color(0xFF420B20) // Dark muted pink
    
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
    val errorCount by ProxyStats.errors.collectAsStateWithLifecycle(initialValue = 0L)
    val serviceStatuses by ServiceChecker.statuses.collectAsStateWithLifecycle(initialValue = emptyList())
    val isProxyHealthy by ServiceChecker.proxyHealth.collectAsStateWithLifecycle(initialValue = true)
    val isInternetUp by ServiceChecker.internetAvailable.collectAsStateWithLifecycle(initialValue = true)
    val lastCheckTime by ServiceChecker.lastCheckTime.collectAsStateWithLifecycle(initialValue = 0L)

    val recoveryLog by ProxyStats.recoveryLog.collectAsStateWithLifecycle(initialValue = emptyList())
    val activeStrategy by BypassConfig.strategy.collectAsStateWithLifecycle(initialValue = BypassStrategy.SNI_SPLIT)
    
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
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .background(
                                color = if (!isInternetUp) Color(0xFF9E9E9E) else if (isProxyHealthy) Color(0xFF81C784) else Color(0xFFE57373),
                                shape = CircleShape
                            )
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = when {
                            !isInternetUp -> stringResource(R.string.status_no_internet)
                            !isProxyHealthy -> stringResource(R.string.status_recovery)
                            else -> stringResource(R.string.status_autopilot)
                        },
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (!isInternetUp) Color(0xFF9E9E9E) else if (isProxyHealthy) Color(0xFF81C784) else Color(0xFFE57373),
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
                                    val intent = Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
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
                        Text(
                            text = "${ProxyStats.formatBytes(speedBytes)}/s",
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White
                        )
                        Text(
                            text = stringResource(R.string.label_speed),
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
                            color = if (errorCount > 0) Color(0xFFE57373) else Color.White
                        )
                        Text(
                            text = stringResource(R.string.label_errors),
                            fontSize = 10.sp,
                            color = Color(0xFFF8BBD0).copy(alpha = 0.5f),
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            } else {
                Spacer(modifier = Modifier.height(86.dp))
            }
            
            val buttonColor by animateColorAsState(
                targetValue = if (isActive) Color(0xFFB0124D) else Color.White.copy(alpha = 0.05f),
                animationSpec = tween(500), label = "btnColor"
            )
            
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
                        .background(if (isActive) Color(0xFF7A0A38) else Color(0xFF1A030D))
                ) {
                    Icon(
                        imageVector = Icons.Default.PowerSettingsNew,
                        contentDescription = "Power",
                        tint = if (isActive) Color(0xFFF8BBD0) else Color(0xFF880E4F),
                        modifier = Modifier.size(56.dp)
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Text(
                text = if (isActive) stringResource(R.string.label_secure_tunnel_active) else stringResource(R.string.label_system_offline),
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                color = if (isActive) Color(0xFFF8BBD0) else Color(0xFFAD1457)
            )
            
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
                        color = Color.White.copy(alpha = 0.4f),
                        letterSpacing = 1.sp
                    )
                    val youtubeDown = serviceStatuses.any { it.name == "YouTube" && !it.isUp }
                    val isOptimizing = !isProxyHealthy || youtubeDown
                    
                    Text(
                        text = if (isOptimizing) stringResource(R.string.action_force_reoptimize) else stringResource(R.string.action_optimize),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (isOptimizing) Color.White else Color(0xFFF48FB1),
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
                val youtubeStatus = serviceStatuses.find { it.name == "YouTube" }
                val blockDetected = youtubeStatus != null && !youtubeStatus.isUp && serviceStatuses.any { it.name.contains("Control") && it.isUp }
                
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = stringResource(R.string.label_active_strategy, activeStrategy.name),
                        fontSize = 8.sp,
                        color = Color.White.copy(alpha = 0.3f),
                        modifier = Modifier.padding(bottom = 4.dp)
                    )
                    if (blockDetected) {
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = stringResource(R.string.msg_block_detected),
                            fontSize = 8.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFFE57373),
                            modifier = Modifier.padding(bottom = 4.dp)
                        )
                    }
                }
                val logsScrollState = rememberScrollState()
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 120.dp)
                        .background(Color.Black.copy(alpha = 0.3f), RoundedCornerShape(8.dp))
                        .verticalScroll(logsScrollState)
                        .padding(8.dp)
                ) {
                    recoveryLog.forEach { log ->
                        Text(
                            text = log,
                            color = if (log.contains("Healing") || log.contains("Optimizing")) Color(0xFFF06292) else Color(0xFFF48FB1).copy(alpha = 0.6f),
                            fontSize = 9.sp,
                            fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                            modifier = Modifier.padding(vertical = 1.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
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
                        color = Color.White.copy(alpha = 0.4f),
                        letterSpacing = 1.sp
                    )
                    if (lastCheckTime > 0) {
                        Text(
                            text = stringResource(R.string.label_updated, SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(lastCheckTime))),
                            fontSize = 9.sp,
                            color = Color.White.copy(alpha = 0.3f),
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color.White.copy(alpha = 0.03f), RoundedCornerShape(16.dp))
                        .padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    serviceStatuses.forEach { status ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(Color.White.copy(alpha = 0.02f), RoundedCornerShape(8.dp))
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column {
                                Text(
                                    text = status.name,
                                    color = Color.White,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = status.url.removePrefix("https://").removePrefix("www."),
                                    color = Color.White.copy(alpha = 0.3f),
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
        }
    }
}
