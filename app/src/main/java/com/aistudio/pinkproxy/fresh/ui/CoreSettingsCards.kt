package com.aistudio.pinkproxy.fresh.ui

import android.content.Context
import android.content.Intent
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
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
import com.aistudio.pinkproxy.fresh.R
import com.aistudio.pinkproxy.fresh.ui.theme.GentleDarkPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink

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
