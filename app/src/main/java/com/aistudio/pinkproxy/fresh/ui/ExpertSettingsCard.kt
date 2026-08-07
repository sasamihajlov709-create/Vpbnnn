package com.aistudio.pinkproxy.fresh.ui

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aistudio.pinkproxy.fresh.*
import com.aistudio.pinkproxy.fresh.R
import com.aistudio.pinkproxy.fresh.ui.theme.GentleDarkPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink
import com.aistudio.pinkproxy.fresh.ui.theme.PureBlack

@Composable
fun ExpertSettingsCard(
    context: Context,
    isVpnActive: Boolean
) {
    var expanded by remember { mutableStateOf(false) }

    var isAutoTuning by remember { mutableStateOf(BypassConfig.isAutoTuning) }
    var isDiagnosticModeState by remember { mutableStateOf(BypassConfig.isDiagnosticMode) }
    var autoConnect by remember { mutableStateOf(context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE).getBoolean("auto_connect_on_launch", false)) }

    val customServices by ServiceChecker.customServices.collectAsStateWithLifecycle(initialValue = emptyList())
    var newServiceName by remember { mutableStateOf("") }
    var newServiceUrl by remember { mutableStateOf("") }

    LaunchedEffect(expanded) {
        if (expanded) {
            isAutoTuning = BypassConfig.isAutoTuning
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
                    val isKillSwitchEnabled by BypassConfig.isKillSwitchEnabled.collectAsStateWithLifecycle()
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "SYSTEM-LEVEL KILL SWITCH",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFFE57373)
                        )
                        Text(
                            text = "Блокировать весь трафик вне VPN туннеля (предотвращает утечки)",
                            fontSize = 9.sp,
                            color = Color(0xFFE57373).copy(alpha = 0.6f)
                        )
                    }
                    Switch(
                        checked = isKillSwitchEnabled,
                        onCheckedChange = {
                            BypassConfig.setKillSwitch(it, context)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color(0xFFE57373),
                            checkedTrackColor = Color(0xFFE57373).copy(alpha = 0.5f)
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

                Spacer(modifier = Modifier.height(8.dp))

                val isBenchmarking by BenchmarkManager.isRunning.collectAsStateWithLifecycle()
                val benchmarkProgress by BenchmarkManager.progress.collectAsStateWithLifecycle()
                val benchmarkResults by BenchmarkManager.results.collectAsStateWithLifecycle()
                val scope = rememberCoroutineScope()

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(GentleMediumPink.copy(alpha = 0.05f), RoundedCornerShape(12.dp))
                        .padding(12.dp)
                ) {
                    Text(
                        text = "СТРАТЕГИЧЕСКИЙ БЕНЧМАРК / BENCHMARK",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Black,
                        color = GentleLightPink
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    if (isBenchmarking) {
                        LinearProgressIndicator(
                            progress = { benchmarkProgress },
                            modifier = Modifier.fillMaxWidth().height(4.dp),
                            color = GentleLightPink,
                            trackColor = GentleMediumPink.copy(alpha = 0.2f)
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Проверка стратегий: ${(benchmarkProgress * 100).toInt()}%",
                            fontSize = 9.sp,
                            color = GentleLightPink.copy(alpha = 0.6f)
                        )
                    } else {
                        Button(
                            onClick = { BenchmarkManager.startBenchmark(scope, 18080) },
                            modifier = Modifier.fillMaxWidth().height(32.dp),
                            contentPadding = PaddingValues(0.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = GentleMediumPink.copy(alpha = 0.3f)),
                            enabled = isVpnActive
                        ) {
                            Text("ЗАПУСТИТЬ ТЕСТ ВСЕХ СТРАТЕГИЙ", fontSize = 9.sp, fontWeight = FontWeight.Bold)
                        }
                    }

                    if (benchmarkResults.any { it.isTested }) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Text("ТОП ПО РЕЗУЛЬТАТАМ:", fontSize = 9.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink)
                        benchmarkResults.filter { it.isTested && it.isSuccess }
                            .sortedBy { it.latencyMs }
                            .take(5)
                            .forEach { res ->
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(res.strategy.name, fontSize = 9.sp, color = GentleLightPink)
                                    Text("${res.latencyMs}ms", fontSize = 9.sp, color = Color(0xFF81C784), fontWeight = FontWeight.Bold)
                                }
                            }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                Button(
                    onClick = {
                        RecoveryManager.recalibrateEverything()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = GentleMediumPink.copy(alpha = 0.4f)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth().height(40.dp).padding(bottom = 8.dp),
                    contentPadding = PaddingValues(0.dp),
                    enabled = isVpnActive
                ) {
                    Icon(Icons.Default.Refresh, null, modifier = Modifier.size(16.dp), tint = GentleLightPink)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("FULL SYSTEM RECALIBRATION", fontSize = 11.sp, fontWeight = FontWeight.Black, color = GentleLightPink)
                }

                Button(
                    onClick = {
                        val intent = Intent(context, PinkVpnService::class.java).apply {
                            action = "RESTART"
                        }
                        context.startService(intent)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = GentleMediumPink.copy(alpha = 0.2f)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth().height(36.dp),
                    contentPadding = PaddingValues(0.dp),
                    enabled = isVpnActive
                ) {
                    Text("RESTART CORE ENGINE", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)
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
