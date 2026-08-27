import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ui/ExpertSettingsCard.kt", "r") as f:
    content = f.read()

replacement = """
                Row(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "DYNAMIC ADAPTIVE AUTO-TUNER",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = GentleLightPink
                        )
                        Text(
                            text = "Автоматическая тонкая подстройка параметров сплита при сбоях",
                            fontSize = 9.sp,
                            color = GentleLightPink.copy(alpha = 0.4f)
                        )
                    }
                    Switch(
                        checked = isAutoTuning,
                        onCheckedChange = {
                            isAutoTuning = it
                            BypassConfig.isAutoTuning = it
                            BypassConfig.saveTuningSettings(context)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = GentleMediumPink,
                            checkedTrackColor = GentleMediumPink.copy(alpha = 0.5f)
                        )
                    )
                }

                if (!isAutoTuning) {
                    var frag1 by remember { mutableStateOf(BypassConfig.frag1.toFloat()) }
                    var frag2 by remember { mutableStateOf(BypassConfig.frag2.toFloat()) }
                    var frag3 by remember { mutableStateOf(BypassConfig.frag3.toFloat()) }

                    Text("Размер первого фрагмента (SNI Mangle)", fontSize = 10.sp, color = GentleLightPink.copy(alpha=0.6f))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Slider(
                            value = frag1,
                            onValueChange = { frag1 = it },
                            onValueChangeFinished = { 
                                BypassConfig.frag1 = frag1.toInt()
                                BypassConfig.saveTuningSettings(context)
                            },
                            valueRange = 1f..100f,
                            modifier = Modifier.weight(1f),
                            colors = SliderDefaults.colors(thumbColor = GentleMediumPink, activeTrackColor = GentleMediumPink)
                        )
                        Text("${frag1.toInt()} bytes", fontSize = 10.sp, color = GentleLightPink, modifier = Modifier.width(50.dp).padding(start = 8.dp))
                    }

                    Text("Размер второго фрагмента", fontSize = 10.sp, color = GentleLightPink.copy(alpha=0.6f))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Slider(
                            value = frag2,
                            onValueChange = { frag2 = it },
                            onValueChangeFinished = { 
                                BypassConfig.frag2 = frag2.toInt()
                                BypassConfig.saveTuningSettings(context)
                            },
                            valueRange = 0f..200f,
                            modifier = Modifier.weight(1f),
                            colors = SliderDefaults.colors(thumbColor = GentleMediumPink, activeTrackColor = GentleMediumPink)
                        )
                        Text(if(frag2.toInt() == 0) "Auto" else "${frag2.toInt()} bytes", fontSize = 10.sp, color = GentleLightPink, modifier = Modifier.width(50.dp).padding(start = 8.dp))
                    }

                    Text("Размер третьего фрагмента", fontSize = 10.sp, color = GentleLightPink.copy(alpha=0.6f))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Slider(
                            value = frag3,
                            onValueChange = { frag3 = it },
                            onValueChangeFinished = { 
                                BypassConfig.frag3 = frag3.toInt()
                                BypassConfig.saveTuningSettings(context)
                            },
                            valueRange = 0f..300f,
                            modifier = Modifier.weight(1f),
                            colors = SliderDefaults.colors(thumbColor = GentleMediumPink, activeTrackColor = GentleMediumPink)
                        )
                        Text(if(frag3.toInt() == 0) "Auto" else "${frag3.toInt()} bytes", fontSize = 10.sp, color = GentleLightPink, modifier = Modifier.width(50.dp).padding(start = 8.dp))
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                }
"""

content = re.sub(
    r'                Row\(\n                    modifier = Modifier\.fillMaxWidth\(\)\.padding\(bottom = 12\.dp\),\n                    horizontalArrangement = Arrangement\.SpaceBetween,\n                    verticalAlignment = Alignment\.CenterVertically\n                \) \{\n                    Column\(modifier = Modifier\.weight\(1f\)\) \{\n                        Text\(\n                            text = "DYNAMIC ADAPTIVE AUTO-TUNER",.*?colors = SwitchDefaults\.colors\(\n                            checkedThumbColor = GentleMediumPink,\n                            checkedTrackColor = GentleMediumPink\.copy\(alpha = 0\.5f\)\n                        \)\n                    \)\n                \}', 
    replacement.strip("\n"), 
    content, 
    flags=re.DOTALL
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ui/ExpertSettingsCard.kt", "w") as f:
    f.write(content)
