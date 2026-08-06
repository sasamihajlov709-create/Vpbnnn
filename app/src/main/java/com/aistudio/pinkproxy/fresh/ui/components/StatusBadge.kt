package com.aistudio.pinkproxy.fresh.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink

@Composable
fun StatusBadge(isProxyHealthy: Boolean, isInternetUp: Boolean, isProbing: Boolean) {
    Surface(
        color = Color.Black.copy(alpha = 0.4f),
        shape = CircleShape,
        border = androidx.compose.foundation.BorderStroke(1.dp, GentleMediumPink.copy(alpha = 0.2f))
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .background(
                        when {
                            isProbing -> Color(0xFF4FC3F7)
                            isProxyHealthy && isInternetUp -> Color(0xFF81C784)
                            else -> Color(0xFFE57373)
                        },
                        CircleShape
                    )
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = when {
                    isProbing -> "SCANNING..."
                    isProxyHealthy && isInternetUp -> "SECURED & OPTIMIZED"
                    !isInternetUp -> "OFFLINE"
                    else -> "BYPASS STALLED"
                },
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                color = GentleLightPink.copy(alpha = 0.8f),
                letterSpacing = 1.sp
            )
        }
    }
}
