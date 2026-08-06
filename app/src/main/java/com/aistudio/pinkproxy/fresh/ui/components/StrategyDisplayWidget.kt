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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import com.aistudio.pinkproxy.fresh.BypassStrategy
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink
import com.aistudio.pinkproxy.fresh.ui.theme.PureBlack

@Composable
fun StrategyDisplayWidget(
    activeStrategy: BypassStrategy,
    testingStrategies: List<BypassStrategy>,
    isProbing: Boolean,
    isActive: Boolean,
    onSelectStrategy: () -> Unit
) {
    Surface(
        color = PureBlack.copy(alpha = 0.5f),
        shape = RoundedCornerShape(20.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, GentleMediumPink.copy(alpha = 0.15f)),
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onSelectStrategy() }
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "ACTIVE EVASION STRATEGY",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = GentleMediumPink,
                        letterSpacing = 1.sp
                    )
                    Text(
                        text = activeStrategy.name.replace("_", " "),
                        fontSize = 18.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = GentleLightPink
                    )
                }
                
                if (isActive) {
                    Box(
                        modifier = Modifier
                            .size(36.dp)
                            .clip(CircleShape)
                            .background(GentleMediumPink.copy(alpha = 0.1f))
                            .clickable { onSelectStrategy() },
                        contentAlignment = Alignment.Center
                    ) {
                        androidx.compose.material3.Icon(
                            imageVector = androidx.compose.material.icons.Icons.Default.Settings,
                            contentDescription = "Config",
                            tint = GentleMediumPink,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }
            
            if (isActive && testingStrategies.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = if (isProbing) "AUTONOMOUS PROBING ACTIVE" else "AUTONOMOUS ENGINE STATUS",
                    fontSize = 8.sp,
                    fontWeight = FontWeight.Bold,
                    color = if (isProbing) Color(0xFF4FC3F7) else GentleMediumPink.copy(alpha = 0.4f),
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(6.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    testingStrategies.take(5).forEach { strat ->
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .height(4.dp)
                                .clip(RoundedCornerShape(2.dp))
                                .background(
                                    if (strat == activeStrategy) GentleMediumPink 
                                    else if (isProbing) Color(0xFF4FC3F7).copy(alpha = 0.3f)
                                    else GentleMediumPink.copy(alpha = 0.1f)
                                )
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun StrategyStatsDialog(onDismiss: () -> Unit) {
    // This will be implemented or moved from MainActivity
}
