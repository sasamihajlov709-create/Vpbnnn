package com.aistudio.pinkproxy.fresh.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aistudio.pinkproxy.fresh.BypassConfig
import com.aistudio.pinkproxy.fresh.BypassStrategy
import com.aistudio.pinkproxy.fresh.ui.theme.GentleDarkPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun TestingStrategiesSelectionCard() {
    val testingStrategies by BypassConfig.testingStrategies.collectAsStateWithLifecycle()
    var expanded by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .border(1.dp, GentleMediumPink.copy(alpha = 0.2f), RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.Black.copy(alpha = 0.5f))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { expanded = !expanded },
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "ALLOWED STRATEGIES",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = GentleLightPink
                    )
                    Text(
                        text = "Select strategies available for rotation and testing",
                        fontSize = 11.sp,
                        color = GentleLightPink.copy(alpha = 0.6f),
                        lineHeight = 14.sp
                    )
                }
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.List,
                    contentDescription = null,
                    tint = GentleMediumPink,
                    modifier = Modifier.size(24.dp)
                )
            }

            if (expanded) {
                Spacer(modifier = Modifier.height(16.dp))
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    BypassStrategy.entries.filter { it != BypassStrategy.DIRECT }.forEach { strategy ->
                        val isSelected = testingStrategies.contains(strategy)
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = if (isSelected) GentleDarkPink else Color.White.copy(alpha = 0.05f),
                            border = androidx.compose.foundation.BorderStroke(
                                1.dp,
                                if (isSelected) GentleMediumPink else Color.White.copy(alpha = 0.1f)
                            ),
                            modifier = Modifier.clickable {
                                val currentList = testingStrategies.toMutableList()
                                if (isSelected) {
                                    if (currentList.size > 1) { // prevent removing all
                                        currentList.remove(strategy)
                                        BypassConfig.updateTestingStrategies(currentList)
                                    }
                                } else {
                                    currentList.add(strategy)
                                    BypassConfig.updateTestingStrategies(currentList)
                                }
                            }
                        ) {
                            Text(
                                text = strategy.name.replace("_", " "),
                                fontSize = 10.sp,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                                color = GentleLightPink,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}
