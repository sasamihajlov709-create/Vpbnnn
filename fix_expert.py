import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/ExpertSettingsCard.kt', 'r') as f:
    content = f.read()

import_quic = "import com.aistudio.pinkproxy.fresh.QuicBypassMode\n"
if "QuicBypassMode" not in content:
    content = content.replace("import com.aistudio.pinkproxy.fresh.R", "import com.aistudio.pinkproxy.fresh.R\nimport com.aistudio.pinkproxy.fresh.QuicBypassMode")

# Add state
content = content.replace(
    "var isDiagnosticModeState by remember { mutableStateOf(BypassConfig.isDiagnosticMode) }",
    "var isDiagnosticModeState by remember { mutableStateOf(BypassConfig.isDiagnosticMode) }\n    val quicBypassMode by BypassConfig.quicBypassMode.collectAsStateWithLifecycle()"
)

# UI for QUIC Bypass Mode
quic_ui = """                Spacer(modifier = Modifier.height(16.dp))
                Text("UDP QUIC BYPASS MODE", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleMediumPink)
                Row(
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    QuicBypassMode.entries.forEach { mode ->
                        val isSelected = mode == quicBypassMode
                        Button(
                            onClick = { BypassConfig.setQuicBypassMode(mode) },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (isSelected) GentleDarkPink else GentleMediumPink.copy(alpha = 0.2f)
                            ),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f).height(32.dp),
                            contentPadding = PaddingValues(0.dp)
                        ) {
                            Text(mode.name.replace("_", " "), fontSize = 9.sp, color = GentleLightPink)
                        }
                    }
                }
"""

content = content.replace(
    'Text("ДОБАВИТЬ СЕРВИС В ПРОВЕРКУ", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)\n                }',
    'Text("ДОБАВИТЬ СЕРВИС В ПРОВЕРКУ", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = GentleLightPink)\n                }\n' + quic_ui
)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/ExpertSettingsCard.kt', 'w') as f:
    f.write(content)
