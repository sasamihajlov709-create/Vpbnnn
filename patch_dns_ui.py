import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ui/DnsSettingsCard.kt", "r") as f:
    content = f.read()

replacement = """
    var dnsType by remember { mutableStateOf(BypassConfig.dnsType) }
    var customUrl by remember { mutableStateOf(BypassConfig.customDnsUrl) }
    var showDialog by remember { mutableStateOf(false) }

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
                        text = stringResource(R.string.label_dns_strategy),
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Bold,
                        color = GentleLightPink
                    )
                    Text(
                        text = stringResource(R.string.desc_dns_strategy),
                        fontSize = 11.sp,
                        color = GentleLightPink.copy(alpha = 0.6f),
                        lineHeight = 14.sp
                    )
                }
                Icon(
                    imageVector = Icons.Default.Dns,
                    contentDescription = null,
                    tint = GentleMediumPink,
                    modifier = Modifier.size(24.dp)
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
                    text = "${stringResource(R.string.label_current_dns)}: ${dnsType.name}",
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    color = GentleLightPink
                )
            }

            if (dnsType == DnsType.CUSTOM_DOH || dnsType == DnsType.CUSTOM_TCP || dnsType == DnsType.CUSTOM_UDP) {
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedTextField(
                    value = customUrl,
                    onValueChange = { 
                        customUrl = it
                        BypassConfig.saveDnsSettings(context, dnsType, customUrl)
                    },
                    label = { Text("Custom DNS URL / IP", color = GentleLightPink.copy(alpha = 0.6f)) },
                    textStyle = androidx.compose.ui.text.TextStyle(color = GentleLightPink),
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = GentleMediumPink,
                        unfocusedBorderColor = GentleMediumPink.copy(alpha = 0.3f),
                        cursorColor = GentleMediumPink
                    )
                )
            }
        }
    }

    if (showDialog) {
        DnsSelectionDialog(
            context = context,
            currentType = dnsType,
            onDismiss = { showDialog = false },
            onSelected = { newType ->
                dnsType = newType
                BypassConfig.saveDnsSettings(context, newType, customUrl)
                onSettingsChanged()
            }
        )
    }
}
"""

content = re.sub(r'    var dnsType by remember \{ mutableStateOf\(BypassConfig.dnsType\) \}.*?\}\n\}\n', replacement.lstrip(), content, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ui/DnsSettingsCard.kt", "w") as f:
    f.write(content)
