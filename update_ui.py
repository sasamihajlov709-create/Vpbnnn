import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/MainActivity.kt', 'r') as f:
    content = f.read()

find = """                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.clickable {
                                    BypassConfig.isAutoTuning = !BypassConfig.isAutoTuning
                                    BypassConfig.saveTuningSettings(context)
                                }.padding(vertical = 2.dp)
                            ) {
                                Text("Auto-Tuning: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text(if (BypassConfig.isAutoTuning) "ACTIVE (Tap to disable)" else "MANUAL (Tap to enable)", fontSize = 11.sp, color = if (BypassConfig.isAutoTuning) Color(0xFF81C784) else Color(0xFFFFB74D), fontWeight = FontWeight.Bold)
                            }
                        }"""

repl = """                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.clickable {
                                    BypassConfig.isAutoTuning = !BypassConfig.isAutoTuning
                                    BypassConfig.saveTuningSettings(context)
                                }.padding(vertical = 2.dp)
                            ) {
                                Text("Auto-Tuning: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text(if (BypassConfig.isAutoTuning) "ACTIVE (Tap to disable)" else "MANUAL (Tap to enable)", fontSize = 11.sp, color = if (BypassConfig.isAutoTuning) Color(0xFF81C784) else Color(0xFFFFB74D), fontWeight = FontWeight.Bold)
                            }
                            
                            val cwnd by ProxyStats.congestionWindow.collectAsStateWithLifecycle(initialValue = 10)
                            val poolSize by ProxyStats.pool16kSize.collectAsStateWithLifecycle(initialValue = 0)
                            
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 2.dp)) {
                                Text("Congestion Window: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text("${cwnd} pkts/burst", fontSize = 11.sp, color = Color(0xFFBA68C8), fontWeight = FontWeight.Bold)
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("Buffer Pool (16K): ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text("$poolSize chunks", fontSize = 11.sp, color = Color(0xFF4FC3F7), fontWeight = FontWeight.Bold)
                            }
                        }"""

if find in content:
    content = content.replace(find, repl)
    
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/MainActivity.kt', 'w') as f:
    f.write(content)
