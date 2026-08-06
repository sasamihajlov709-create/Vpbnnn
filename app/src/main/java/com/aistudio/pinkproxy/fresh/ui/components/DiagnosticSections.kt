package com.aistudio.pinkproxy.fresh.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aistudio.pinkproxy.fresh.HostCategory
import com.aistudio.pinkproxy.fresh.HostClassifier
import com.aistudio.pinkproxy.fresh.ProxyStats
import com.aistudio.pinkproxy.fresh.ActiveFlow
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink

@Composable
fun ActiveFlowsContent(flows: List<ActiveFlow>) {
    Column(
        modifier = Modifier
            .padding(top = 8.dp)
            .fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        if (flows.isEmpty()) {
            Text("NO ACTIVE FLOWS", fontSize = 10.sp, color = GentleLightPink.copy(alpha = 0.3f), modifier = Modifier.padding(8.dp))
        } else {
            flows.take(15).forEach { flow ->
                ActiveFlowItem(flow)
            }
        }
    }
}

@Composable
fun ActiveFlowItem(flow: ActiveFlow) {
    val category = HostClassifier.classify(flow.host)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color.White.copy(alpha = 0.03f), RoundedCornerShape(8.dp))
            .padding(horizontal = 10.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(6.dp)
                .background(
                    when(category) {
                        HostCategory.AI -> Color(0xFFCE93D8)
                        HostCategory.STREAMING -> Color(0xFFE57373)
                        HostCategory.MESSENGER -> Color(0xFF81C784)
                        HostCategory.SOCIAL -> Color(0xFF64B5F6)
                        else -> GentleMediumPink.copy(alpha = 0.5f)
                    },
                    CircleShape
                )
        )
        Spacer(modifier = Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(flow.host, color = GentleLightPink, fontSize = 11.sp, fontWeight = FontWeight.Bold, maxLines = 1)
            Text(flow.strategy.name.replace("_", " "), color = GentleMediumPink.copy(alpha = 0.6f), fontSize = 8.sp)
        }
        Text(
            text = flow.type,
            color = if (flow.type == "UDP") Color(0xFFBA68C8) else Color(0xFF4FC3F7),
            fontSize = 9.sp,
            fontWeight = FontWeight.Bold
        )
    }
}
