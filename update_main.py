import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/MainActivity.kt', 'r') as f:
    content = f.read()

find = """                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("Buffer Pool (16K): ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text("$poolSize chunks", fontSize = 11.sp, color = Color(0xFF4FC3F7), fontWeight = FontWeight.Bold)
                            }"""

repl = """                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text("Buffer Pool (16K): ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text("$poolSize chunks", fontSize = 11.sp, color = Color(0xFF4FC3F7), fontWeight = FontWeight.Bold)
                            }
                            
                            val isPanic by BypassConfig.isPanicModeFlow.collectAsStateWithLifecycle(initialValue = BypassConfig.isPanicMode)
                            val mtu by BypassConfig.currentMtu.collectAsStateWithLifecycle()
                            
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 2.dp)) {
                                Text("Network MTU: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                Text("$mtu bytes", fontSize = 11.sp, color = Color(0xFF81C784), fontWeight = FontWeight.Bold)
                            }
                            if (isPanic) {
                                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 2.dp)) {
                                    Text("Status: ", fontSize = 11.sp, color = Color(0xFFF8BBD0).copy(alpha = 0.6f))
                                    Text("PANIC MODE", fontSize = 11.sp, color = Color(0xFFE57373), fontWeight = FontWeight.ExtraBold)
                                }
                            }"""
                            
if find in content:
    content = content.replace(find, repl)
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/MainActivity.kt', 'w') as f:
        f.write(content)
