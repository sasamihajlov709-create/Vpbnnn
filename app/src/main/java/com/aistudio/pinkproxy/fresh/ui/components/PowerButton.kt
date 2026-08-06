package com.aistudio.pinkproxy.fresh.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.aistudio.pinkproxy.fresh.VpnLifecycleState
import com.aistudio.pinkproxy.fresh.ui.theme.GentleDeepPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleMediumPink

@Composable
fun PowerButton(
    vpnState: VpnLifecycleState,
    onToggle: () -> Unit,
    infiniteTransition: InfiniteTransition
) {
    val isActive = vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING
    val isConnecting = vpnState == VpnLifecycleState.STARTING || vpnState == VpnLifecycleState.STOPPING
    
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = if (isActive) 1.08f else 1.02f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ), label = "pulse"
    )

    val shadowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.2f,
        targetValue = if (isActive) 0.6f else 0.3f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ), label = "shadow"
    )

    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .size(200.dp)
            .scale(pulseScale)
    ) {
        // Outer glow
        Box(
            modifier = Modifier
                .size(160.dp)
                .blur(30.dp)
                .background(
                    if (isActive) GentleDeepPink.copy(alpha = shadowAlpha) 
                    else GentleMediumPink.copy(alpha = shadowAlpha / 2),
                    CircleShape
                )
        )
        
        // Button surface
        Surface(
            onClick = onToggle,
            enabled = !isConnecting,
            shape = CircleShape,
            color = Color(0xFF1A1A1A),
            tonalElevation = 8.dp,
            border = BorderStroke(
                if (isActive) 3.dp else 1.dp,
                if (isActive) GentleMediumPink else GentleLightPink.copy(alpha = 0.2f)
            ),
            modifier = Modifier
                .size(140.dp)
                .clickable(enabled = !isConnecting) { onToggle() }
        ) {
            Box(contentAlignment = Alignment.Center) {
                if (isConnecting) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(80.dp),
                        color = GentleMediumPink,
                        strokeWidth = 3.dp
                    )
                }
                Icon(
                    imageVector = Icons.Default.PowerSettingsNew,
                    contentDescription = if (isActive) "Stop VPN" else "Start VPN",
                    modifier = Modifier.size(64.dp),
                    tint = if (isActive) GentleLightPink else GentleMediumPink.copy(alpha = 0.4f)
                )
            }
        }
    }
}
