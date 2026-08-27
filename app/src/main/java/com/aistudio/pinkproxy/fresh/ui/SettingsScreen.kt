package com.aistudio.pinkproxy.fresh.ui

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aistudio.pinkproxy.fresh.R
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink
import com.aistudio.pinkproxy.fresh.ui.theme.PureBlack

@Composable
fun SettingsScreen(
    context: Context,
    isVpnActive: Boolean,
    onSettingsChanged: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(PureBlack)
    ) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(top = 16.dp, bottom = 32.dp)
        ) {
            item {
                Text(
                    text = stringResource(R.string.title_settings),
                    fontSize = 24.sp,
                    fontWeight = FontWeight.ExtraBold,
                    color = GentleLightPink,
                    modifier = Modifier.padding(bottom = 16.dp, top = 8.dp)
                )
            }

            item { StrategySettingsCard(context, onSettingsChanged) }
            item { DnsSettingsCard(context, onSettingsChanged) }
            item { ProfileBackupCard(context, onSettingsChanged) }
            item { MtuSettingsCard(context) }
            item { AppFilterCard(context, onSettingsChanged) }
            item { AutoConnectCard(context) }
            item { BatteryOptimizationInfoCard(context) }
            item { ExpertSettingsCard(context, isVpnActive) }

            item {
                Spacer(modifier = Modifier.height(24.dp))
                Text(
                    text = "PinkProxy Engine v2.5.0-fresh",
                    fontSize = 10.sp,
                    color = GentleLightPink.copy(alpha = 0.3f),
                    modifier = Modifier.padding(bottom = 16.dp)
                )
            }
        }
    }
}
