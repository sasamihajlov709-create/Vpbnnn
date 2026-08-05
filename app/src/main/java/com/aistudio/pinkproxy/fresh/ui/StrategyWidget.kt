package com.aistudio.pinkproxy.fresh.ui

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aistudio.pinkproxy.fresh.BypassStrategy
import com.aistudio.pinkproxy.fresh.StrategyGroup
import com.aistudio.pinkproxy.fresh.ui.theme.GentleDarkPink
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
    val infiniteTransition = rememberInfiniteTransition(label = "strat_pulse")
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.4f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1200, easing = LinearEasing), RepeatMode.Reverse),
        label = "pulse_alpha"
    )

    val activeGroupColor = when (activeStrategy.group) {
        StrategyGroup.LIGHT -> Color(0xFF81C784)
        StrategyGroup.MEDIUM -> GentleLightPink
        StrategyGroup.HEAVY -> Color(0xFFFFB74D)
        StrategyGroup.EXTREME -> Color(0xFFE57373)
    }

    Surface(
        color = PureBlack,
        shape = RoundedCornerShape(24.dp),
        border = BorderStroke(
            width = 1.dp,
            color = if (isProbing) GentleMediumPink.copy(alpha = pulseAlpha) else GentleMediumPink.copy(alpha = 0.15f)
        ),
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onSelectStrategy() }
            .testTag("strategy_display_widget")
    ) {
        Column(
            modifier = Modifier
                .padding(horizontal = 18.dp, vertical = 16.dp)
        ) {
            // Header Row: Active Working Strategy Title & Status
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .background(
                                color = if (isActive) Color(0xFF81C784) else GentleMediumPink.copy(alpha = 0.5f),
                                shape = CircleShape
                            )
                    )
                    Text(
                        text = "АКТИВНАЯ СТРАТЕГИЯ",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Black,
                        color = GentleLightPink.copy(alpha = 0.7f),
                        letterSpacing = 1.2.sp
                    )
                }

                Surface(
                    color = activeGroupColor.copy(alpha = 0.15f),
                    shape = RoundedCornerShape(8.dp),
                    border = BorderStroke(1.dp, activeGroupColor.copy(alpha = 0.3f))
                ) {
                    Text(
                        text = activeStrategy.group.name,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold,
                        color = activeGroupColor,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Main Active Strategy Display
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = activeStrategy.name.replace("_", " "),
                        fontSize = 18.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = GentleLightPink,
                        letterSpacing = (-0.5).sp
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "Семейство: ${activeStrategy.family.name} • Затраты: ${activeStrategy.cost}/10 • Риск: ${activeStrategy.risk}/10",
                        fontSize = 10.sp,
                        color = GentleLightPink.copy(alpha = 0.5f)
                    )
                }

                Icon(
                    imageVector = Icons.Default.KeyboardArrowDown,
                    contentDescription = "Настроить стратегии",
                    tint = GentleLightPink.copy(alpha = 0.6f),
                    modifier = Modifier.size(20.dp)
                )
            }

            Spacer(modifier = Modifier.height(14.dp))
            HorizontalDivider(color = GentleMediumPink.copy(alpha = 0.12f), thickness = 1.dp)
            Spacer(modifier = Modifier.height(12.dp))

            // Testing / Probing Section Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    if (isProbing) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(10.dp),
                            color = GentleLightPink,
                            strokeWidth = 1.5.dp
                        )
                    } else {
                        Box(
                            modifier = Modifier
                                .size(6.dp)
                                .background(GentleMediumPink.copy(alpha = 0.6f), CircleShape)
                        )
                    }

                    Text(
                        text = if (isProbing) "ИДЕТ ПЕРЕБОР И АВТОПОДБОР..." else "ПЕРЕБОР И ТЕСТИРОВАНИЕ СТРАТЕГИЙ",
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (isProbing) GentleLightPink else GentleLightPink.copy(alpha = 0.5f),
                        letterSpacing = 0.8.sp
                    )
                }

                Text(
                    text = "${testingStrategies.size} в пуле",
                    fontSize = 9.sp,
                    color = GentleLightPink.copy(alpha = 0.4f)
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Chips of strategies being tested/evaluated
            OptStrategyChipsRow(
                activeStrategy = activeStrategy,
                testingStrategies = testingStrategies,
                isProbing = isProbing
            )
        }
    }
}

@Composable
fun OptStrategyChipsRow(
    activeStrategy: BypassStrategy,
    testingStrategies: List<BypassStrategy>,
    isProbing: Boolean
) {
    val displayList = remember(activeStrategy, testingStrategies) {
        (listOf(activeStrategy) + testingStrategies).distinct().take(6)
    }

    OptFlowRow(
        horizontalSpacing = 6.dp,
        verticalSpacing = 6.dp,
        modifier = Modifier.fillMaxWidth()
    ) {
        displayList.forEach { strat ->
            val isActive = strat == activeStrategy

            val chipBg = if (isActive) GentleDarkPink.copy(alpha = 0.35f) else GentleLightPink.copy(alpha = 0.06f)
            val chipBorder = if (isActive) GentleLightPink.copy(alpha = 0.6f) else GentleMediumPink.copy(alpha = 0.15f)
            val chipTextColor = if (isActive) GentleLightPink else GentleLightPink.copy(alpha = 0.6f)

            Surface(
                color = chipBg,
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(1.dp, chipBorder)
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 9.dp, vertical = 5.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    if (isActive) {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = "Активна",
                            tint = Color(0xFF81C784),
                            modifier = Modifier.size(11.dp)
                        )
                    } else if (isProbing) {
                        Box(
                            modifier = Modifier
                                .size(5.dp)
                                .background(GentleLightPink.copy(alpha = 0.8f), CircleShape)
                        )
                    }

                    Text(
                        text = strat.name.replace("_", " "),
                        fontSize = 10.sp,
                        fontWeight = if (isActive) FontWeight.Bold else FontWeight.Medium,
                        color = chipTextColor
                    )
                }
            }
        }
    }
}

@Composable
fun OptFlowRow(
    horizontalSpacing: Dp = 6.dp,
    verticalSpacing: Dp = 6.dp,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {
    Layout(
        content = content,
        modifier = modifier
    ) { measurables, constraints ->
        val hSpacingPx = horizontalSpacing.roundToPx()
        val vSpacingPx = verticalSpacing.roundToPx()

        var currentX = 0
        var currentY = 0
        var maxRowHeight = 0

        val placeables = mutableListOf<Pair<androidx.compose.ui.layout.Placeable, Pair<Int, Int>>>()

        for (measurable in measurables) {
            val placeable = measurable.measure(constraints)
            if (currentX + placeable.width > constraints.maxWidth && currentX > 0) {
                currentX = 0
                currentY += maxRowHeight + vSpacingPx
                maxRowHeight = 0
            }
            placeables.add(placeable to Pair(currentX, currentY))
            currentX += placeable.width + hSpacingPx
            maxRowHeight = maxOf(maxRowHeight, placeable.height)
        }

        val totalHeight = (currentY + maxRowHeight).coerceIn(constraints.minHeight, constraints.maxHeight)
        val totalWidth = constraints.maxWidth
        layout(totalWidth, totalHeight) {
            for ((placeable, position) in placeables) {
                placeable.place(position.first, position.second)
            }
        }
    }
}
