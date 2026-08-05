package com.aistudio.pinkproxy.fresh.ui

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aistudio.pinkproxy.fresh.*
import com.aistudio.pinkproxy.fresh.R
import com.aistudio.pinkproxy.fresh.ui.theme.GentleDarkPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink
import com.aistudio.pinkproxy.fresh.ui.theme.PureBlack

@Composable
fun AutoConnectCard(context: Context) {
    val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
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
fun BatteryOptimizationInfoCard(context: Context) {
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
fun AppFilterCard(context: Context, onSettingsChanged: () -> Unit) {
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

@Composable
fun ExpertSettingsCard(
    context: Context,
    isVpnActive: Boolean
) {
    var expanded by remember { mutableStateOf(false) }

    var isAutoTuning by remember { mutableStateOf(BypassConfig.isAutoTuning) }
    var frag1 by remember { mutableStateOf(BypassConfig.frag1.toFloat()) }
    var frag2 by remember { mutableStateOf(BypassConfig.frag2.toFloat()) }
    var frag3 by remember { mutableStateOf(BypassConfig.frag3.toFloat()) }
    var delay1 by remember { mutableStateOf(BypassConfig.delay1.toFloat()) }
    var delay2 by remember { mutableStateOf(BypassConfig.delay2.toFloat()) }
    var fakeTtl by remember { mutableStateOf(BypassConfig.fakeTtl.toFloat()) }

    var dnsMode by remember { mutableStateOf(RobustResolver.dnsMode) }
    var customDnsIp by remember { mutableStateOf(RobustResolver.customDnsIp) }
    var autoConnect by remember { mutableStateOf(context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE).getBoolean("auto_connect_on_launch", false)) }
    var isDiagnosticModeState by remember { mutableStateOf(BypassConfig.isDiagnosticMode) }

    val customServices by ServiceChecker.customServices.collectAsStateWithLifecycle(initialValue = emptyList())
    var newServiceName by remember { mutableStateOf("") }
    var newServiceUrl by remember { mutableStateOf("") }

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
                            context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
                                .edit { putBoolean("auto_connect_on_launch", it) }
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = GentleMediumPink,
                            checkedTrackColor = GentleMediumPink.copy(alpha = 0.5f)
                        )
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "DYNAMIC ADAPTIVE AUTO-TUNER",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = GentleLightPink
                        )
                        Text(
                            text = "Автоматическая тонкая подстройка параметров сплита при сбоях",
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

                // Diagnostic Mode Switch
                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "DIAGNOSTIC & LOGGING MODE",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = GentleLightPink
                        )
                        Text(
                            text = "Расширенная отладка со сбором TCP/DNS трафика",
                            fontSize = 9.sp,
                            color = GentleLightPink.copy(alpha = 0.4f)
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

                HorizontalDivider(color = GentleMediumPink.copy(alpha = 0.1f), modifier = Modifier.padding(vertical = 8.dp))

                // Custom Services Control
                Text(
                    text = "МОНИТОРИНГ И ПРОВЕРКА СЕРВИСОВ",
                    fontSize = 10.sp,
                    fontWeight = FontWeight.ExtraBold,
                    color = GentleMediumPink,
                    modifier = Modifier.padding(bottom = 8.dp)
                )

                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = newServiceName,
                        onValueChange = { newServiceName = it },
                        placeholder = { Text("Название (напр. Notion)", fontSize = 10.sp) },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = GentleMediumPink,
                            unfocusedBorderColor = GentleMediumPink.copy(alpha = 0.3f),
                            focusedTextColor = GentleLightPink,
                            unfocusedTextColor = GentleLightPink
                        )
                    )
                    OutlinedTextField(
                        value = newServiceUrl,
                        onValueChange = { newServiceUrl = it },
                        placeholder = { Text("URL (notion.so)", fontSize = 10.sp) },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = GentleMediumPink,
                            unfocusedBorderColor = GentleMediumPink.copy(alpha = 0.3f),
                            focusedTextColor = GentleLightPink,
                            unfocusedTextColor = GentleLightPink
                        )
                    )
                }

                Button(
                    onClick = {
                        if (newServiceName.isNotBlank() && newServiceUrl.isNotBlank()) {
                            ServiceChecker.addCustomService(context, newServiceName, newServiceUrl)
                            newServiceName = ""
                            newServiceUrl = ""
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = GentleDarkPink),
                    modifier = Modifier.fillMaxWidth().height(36.dp),
                    contentPadding = PaddingValues(0.dp)
                ) {
                    Text("ДОБАВИТЬ СЕРВИС В ПРОВЕРКУ", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)
                }

                if (customServices.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        customServices.forEach { target ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("${target.first} (${target.second})", fontSize = 10.sp, color = GentleLightPink.copy(alpha = 0.8f))
                                IconButton(
                                    onClick = { ServiceChecker.removeCustomService(context, target.first) },
                                    modifier = Modifier.size(24.dp)
                                ) {
                                    Icon(Icons.Default.Delete, null, tint = Color(0xFFE57373), modifier = Modifier.size(14.dp))
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                Button(
                    onClick = {
                        BypassConfig.clearScores(context)
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
