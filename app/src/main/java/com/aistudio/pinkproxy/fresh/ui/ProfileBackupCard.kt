package com.aistudio.pinkproxy.fresh.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.ImportExport
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aistudio.pinkproxy.fresh.BypassConfig
import com.aistudio.pinkproxy.fresh.ui.theme.GentleDarkPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink
import org.json.JSONObject
import android.util.Base64

@Composable
fun ProfileBackupCard(context: Context, onSettingsChanged: () -> Unit) {
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
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "ИМПОРТ / ЭКСПОРТ ПРОФИЛЯ",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = GentleLightPink
                    )
                    Text(
                        text = "Поделитесь идеальными настройками Mangle и DNS через буфер обмена.",
                        fontSize = 11.sp,
                        color = GentleLightPink.copy(alpha = 0.6f),
                        lineHeight = 14.sp
                    )
                }
                Icon(
                    imageVector = Icons.Default.ImportExport,
                    contentDescription = null,
                    tint = GentleMediumPink,
                    modifier = Modifier.size(24.dp)
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
                        val json = JSONObject()
                        prefs.all.forEach { (key, value) -> json.put(key, value) }
                        
                        val base64 = Base64.encodeToString(json.toString().toByteArray(), Base64.NO_WRAP)
                        val payload = "pinkproxy://$base64"
                        
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("PinkProxy Profile", payload))
                        Toast.makeText(context, "Профиль скопирован в буфер", Toast.LENGTH_SHORT).show()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = GentleMediumPink.copy(alpha=0.1f)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f).height(40.dp)
                ) {
                    Icon(Icons.Default.ContentCopy, null, tint = GentleLightPink, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("ЭКСПОРТ", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)
                }

                Button(
                    onClick = {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        if (clipboard.hasPrimaryClip()) {
                            val text = clipboard.primaryClip?.getItemAt(0)?.text?.toString() ?: ""
                            if (text.startsWith("pinkproxy://")) {
                                try {
                                    val base64 = text.removePrefix("pinkproxy://")
                                    val jsonString = String(Base64.decode(base64, Base64.NO_WRAP))
                                    val json = JSONObject(jsonString)
                                    
                                    val prefs = context.getSharedPreferences("pink_proxy_settings", Context.MODE_PRIVATE)
                                    val editor = prefs.edit()
                                    json.keys().forEach { key ->
                                        when (val value = json.get(key)) {
                                            is String -> editor.putString(key, value)
                                            is Boolean -> editor.putBoolean(key, value)
                                            is Int -> editor.putInt(key, value)
                                            is Long -> editor.putLong(key, value)
                                            is Float -> editor.putFloat(key, value)
                                        }
                                    }
                                    editor.apply()
                                    BypassConfig.loadTuningSettings(context)
                                    onSettingsChanged()
                                    Toast.makeText(context, "Профиль успешно применен", Toast.LENGTH_SHORT).show()
                                } catch (e: Exception) {
                                    Toast.makeText(context, "Ошибка импорта: неверный формат", Toast.LENGTH_SHORT).show()
                                }
                            } else {
                                Toast.makeText(context, "В буфере нет профиля PinkProxy", Toast.LENGTH_SHORT).show()
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = GentleDarkPink),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f).height(40.dp)
                ) {
                    Icon(Icons.Default.ContentPaste, null, tint = GentleLightPink, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("ИМПОРТ", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)
                }
            }
        }
    }
}
