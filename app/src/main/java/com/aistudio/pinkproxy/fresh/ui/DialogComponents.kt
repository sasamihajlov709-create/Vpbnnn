package com.aistudio.pinkproxy.fresh.ui

import android.content.Context
import android.content.pm.ApplicationInfo
import android.graphics.drawable.Drawable
import android.widget.ImageView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.aistudio.pinkproxy.fresh.*
import com.aistudio.pinkproxy.fresh.R
import com.aistudio.pinkproxy.fresh.ui.theme.GentleDarkPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink
import com.aistudio.pinkproxy.fresh.ui.theme.PureBlack
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

data class AppEntry(
    val appInfo: ApplicationInfo,
    val label: String,
    val packageName: String
)

@Composable
fun AppIconImage(context: Context, appInfo: ApplicationInfo, label: String) {
    var iconDrawable by remember(appInfo.packageName) { mutableStateOf<Drawable?>(null) }
    
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
                ImageView(ctx).apply {
                    scaleType = ImageView.ScaleType.FIT_CENTER
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
    context: Context,
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
            packages.filter { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 || it.packageName == "com.google.android.youtube" || it.packageName == "org.telegram.messenger" }
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
                                    onCheckedChange = null,
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
fun StrategySelectionDialog(
    currentStrategy: BypassStrategy,
    onDismiss: () -> Unit,
    onSelect: (BypassStrategy) -> Unit
) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth(0.9f)
                .fillMaxHeight(0.8f),
            shape = RoundedCornerShape(24.dp),
            color = PureBlack,
            border = BorderStroke(1.dp, GentleMediumPink.copy(alpha = 0.2f))
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text(
                    text = "ВЫБОР СТРАТЕГИИ ОБХОДА",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Black,
                    color = GentleLightPink,
                    letterSpacing = 1.sp,
                    modifier = Modifier.padding(bottom = 16.dp)
                )
                
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(BypassStrategy.entries.filter { it.implementationStatus == ImplementationStatus.IMPLEMENTED || it.implementationStatus == ImplementationStatus.EXPERIMENTAL }) { strategy ->
                        val isSelected = strategy == currentStrategy
                        val color = when (strategy.group) {
                            StrategyGroup.LIGHT -> Color(0xFF81C784)
                            StrategyGroup.MEDIUM -> GentleLightPink
                            StrategyGroup.HEAVY -> Color(0xFFFFB74D)
                            StrategyGroup.EXTREME -> Color(0xFFE57373)
                        }

                        Surface(
                            onClick = { onSelect(strategy) },
                            color = if (isSelected) color.copy(alpha = 0.15f) else Color.Transparent,
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, if (isSelected) color.copy(alpha = 0.5f) else GentleMediumPink.copy(alpha = 0.1f)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier.padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = strategy.name.replace("_", " "),
                                        color = if (isSelected) color else GentleLightPink,
                                        fontSize = 13.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Text(
                                        text = "${strategy.family.name} • Кост: ${strategy.cost} • Риск: ${strategy.risk}",
                                        color = GentleLightPink.copy(alpha = 0.4f),
                                        fontSize = 10.sp
                                    )
                                }
                                if (isSelected) {
                                    Icon(Icons.Default.CheckCircle, null, tint = color, modifier = Modifier.size(20.dp))
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
                
                Button(
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = GentleMediumPink.copy(alpha = 0.1f)),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Text("ЗАКРЫТЬ", color = GentleLightPink, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

@Composable
fun StrategyStatsDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    var metrics by remember { mutableStateOf(BypassConfig.getStrategyMetrics()) }
    
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
fun DnsSelectionDialog(
    context: Context,
    currentType: DnsType,
    onDismiss: () -> Unit,
    onSelected: (DnsType) -> Unit
) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth(0.9f)
                .fillMaxHeight(0.7f),
            shape = RoundedCornerShape(24.dp),
            color = PureBlack,
            border = BorderStroke(1.dp, GentleMediumPink.copy(alpha = 0.2f))
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text(
                    text = "ВЫБОР DNS СТРАТЕГИИ",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Black,
                    color = GentleLightPink,
                    letterSpacing = 1.sp,
                    modifier = Modifier.padding(bottom = 16.dp)
                )
                
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(DnsType.entries) { type ->
                        val isSelected = type == currentType
                        
                        Surface(
                            onClick = { onSelected(type) },
                            color = if (isSelected) GentleMediumPink.copy(alpha = 0.15f) else Color.Transparent,
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, if (isSelected) GentleMediumPink.copy(alpha = 0.5f) else GentleMediumPink.copy(alpha = 0.1f)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier.padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = type.name.replace("_", " "),
                                        color = if (isSelected) GentleLightPink else GentleLightPink.copy(alpha = 0.8f),
                                        fontSize = 13.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Text(
                                        text = when(type) {
                                            DnsType.AUTO -> "Автоматический выбор (Best Latency)"
                                            DnsType.SYSTEM -> "Системный DNS (через TUN)"
                                            DnsType.GOOGLE_DOH -> "Google Public DNS (DoH)"
                                            DnsType.CLOUDFLARE_DOH -> "Cloudflare DNS (DoH)"
                                            DnsType.ADGUARD_DOH -> "AdGuard DNS (DoH)"
                                            DnsType.QUAD9_DOH -> "Quad9 DNS (DoH)"
                                            DnsType.CUSTOM_DOH -> "Пользовательский DoH URL"
                                            DnsType.CUSTOM_TCP -> "Пользовательский TCP DNS"
                                            DnsType.CUSTOM_UDP -> "Пользовательский UDP DNS"
                                        },
                                        color = GentleLightPink.copy(alpha = 0.4f),
                                        fontSize = 10.sp
                                    )
                                }
                                if (isSelected) {
                                    Icon(Icons.Default.CheckCircle, null, tint = GentleMediumPink, modifier = Modifier.size(20.dp))
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
                
                Button(
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = GentleMediumPink.copy(alpha = 0.1f)),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Text("ЗАКРЫТЬ", color = GentleLightPink, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}
