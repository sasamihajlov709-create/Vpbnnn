package com.aistudio.pinkproxy.fresh.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aistudio.pinkproxy.fresh.DpiAnalyzer
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink

@Composable
fun CensorshipFingerprintCard(fingerprint: DpiAnalyzer.CensorshipFingerprint) {
    Surface(
        color = Color(0xFF12080D).copy(alpha = 0.6f),
        shape = RoundedCornerShape(16.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, GentleMediumPink.copy(alpha = 0.1f)),
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("NETWORK CENSORSHIP FINGERPRINT", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink, letterSpacing = 1.sp)
            Spacer(modifier = Modifier.height(12.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                FingerprintItem("TCP RESET", "${(fingerprint.rstRate * 100).toInt()}%", if (fingerprint.rstRate > 0.3) Color(0xFFE57373) else GentleLightPink)
                FingerprintItem("SNI BLOCK", "${(fingerprint.sniBlockRate * 100).toInt()}%", if (fingerprint.sniBlockRate > 0.4) Color(0xFFE57373) else GentleLightPink)
                FingerprintItem("UDP BLOCK", "${(fingerprint.udpBlockRate * 100).toInt()}%", if (fingerprint.udpBlockRate > 0.5) Color(0xFFE57373) else GentleLightPink)
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                FingerprintItem("TIMEOUTS", "${(fingerprint.timeoutRate * 100).toInt()}%", if (fingerprint.timeoutRate > 0.4) Color(0xFFE57373) else GentleLightPink)
                FingerprintItem("STALLS", "${(fingerprint.stallRate * 100).toInt()}%", if (fingerprint.stallRate > 0.3) Color(0xFFE57373) else GentleLightPink)
                FingerprintItem("JITTER", "${fingerprint.jitter.toInt()}ms", if (fingerprint.jitter > 500) Color(0xFFE57373) else GentleLightPink)
            }
        }
    }
}

@Composable
private fun FingerprintItem(label: String, value: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(label, fontSize = 8.sp, color = GentleLightPink.copy(alpha = 0.4f))
        Text(value, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = color)
    }
}
