import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ServiceChecker.kt', 'r') as f:
    content = f.read()

find = """        // Autopilot Prober: If score is very low, force probe
        if (internetUp && totalWeightedScore < 35f && BypassConfig.isAutoTuning && !isProbing.get()) {
            val now = System.currentTimeMillis()
            if (now - lastProbeTime > 60000) { // Reduced cooldown to 1m for critical situations
                lastProbeTime = now
                appContext?.let { runActiveProbing(it) }
            }
        }"""
repl = """        // Autopilot Prober: If score is very low, force probe
        if (internetUp && totalWeightedScore < 35f && BypassConfig.isAutoTuning && !isProbing.get()) {
            val now = System.currentTimeMillis()
            val cooldown = if (BypassConfig.isCharging) 60000L else 180000L // 3m cooldown on battery
            if (now - lastProbeTime > cooldown) { 
                lastProbeTime = now
                appContext?.let { runActiveProbing(it) }
            }
        }"""

content = content.replace(find, repl)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ServiceChecker.kt', 'w') as f:
    f.write(content)
