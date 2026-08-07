package com.aistudio.pinkproxy.fresh.ui

import android.content.Context
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aistudio.pinkproxy.fresh.PinkVpnService
import com.aistudio.pinkproxy.fresh.R
import com.aistudio.pinkproxy.fresh.ui.theme.GentleDarkPink
import com.aistudio.pinkproxy.fresh.ui.theme.GentleLightPink

@Composable
fun AppFilterCard(context: Context, onSettingsChanged: () -> Unit) {
    var showDialog by remember { mutableStateOf(false) }
    var selectedCount by remember { mutableStateOf(PinkVpnService.selectedPackages.size) }
    var isExcludeMode by remember { mutableStateOf(PinkVpnService.isExcludeMode) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .border(1.dp, GentleLightPink.copy(alpha = 0.2f), RoundedCornerShape(16.dp)),
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
                        text = stringResource(R.string.label_app_filter),
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = GentleLightPink
                    )
                    Text(
                        text = stringResource(R.string.desc_app_filter),
                        fontSize = 11.sp,
                        color = GentleLightPink.copy(alpha = 0.6f),
                        lineHeight = 14.sp
                    )
                }
                Icon(
                    imageVector = Icons.Default.FilterList,
                    contentDescription = null,
                    tint = GentleLightPink,
                    modifier = Modifier.size(24.dp)
                )
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = if (isExcludeMode) stringResource(R.string.label_exclude_mode) else stringResource(R.string.label_include_mode),
                    fontSize = 12.sp,
                    color = GentleLightPink,
                    fontWeight = FontWeight.Medium
                )
                Switch(
                    checked = isExcludeMode,
                    onCheckedChange = {
                        isExcludeMode = it
                        PinkVpnService.isExcludeMode = it
                        PinkVpnService.saveFilterSettings(context)
                        onSettingsChanged()
                    },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = GentleLightPink,
                        checkedTrackColor = GentleDarkPink
                    )
                )
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            Button(
                onClick = { showDialog = true },
                colors = ButtonDefaults.buttonColors(containerColor = GentleDarkPink),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth().height(40.dp)
            ) {
                Text(
                    text = "${stringResource(R.string.action_select_apps)} ($selectedCount)",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = GentleLightPink
                )
            }

            if (!isExcludeMode && selectedCount == 0) {
                Text(
                    text = "WARNING: No apps selected in Include mode. VPN will not route any traffic.",
                    color = Color(0xFFE57373),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
        }
    }

    if (showDialog) {
        AppSelectionDialog(
            context = context,
            onDismiss = { showDialog = false },
            onAppsSelected = { count ->
                selectedCount = count
                PinkVpnService.saveFilterSettings(context)
                onSettingsChanged()
            }
        )
    }
}
