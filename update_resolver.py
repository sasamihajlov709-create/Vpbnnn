import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RobustResolver.kt', 'r') as f:
    content = f.read()

find = """            while (isActive) {
                try {
                    val userTopHosts = ProxyStats.topHosts.value.map { it.first }
                    val combinedHosts = (topHostsToPrefetch + userTopHosts).distinct()
                    
                    combinedHosts.forEach { host ->"""
repl = """            while (isActive) {
                try {
                    val delayMs = if (com.aistudio.pinkproxy.fresh.BypassConfig.isCharging) 3000L else 10000L
                    val userTopHosts = ProxyStats.topHosts.value.map { it.first }
                    val combinedHosts = (topHostsToPrefetch + userTopHosts).distinct()
                    
                    combinedHosts.forEach { host ->"""

find2 = """                        kotlinx.coroutines.delay(2000)
                    }
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                kotlinx.coroutines.delay(5 * 60 * 1000L)"""
repl2 = """                        kotlinx.coroutines.delay(delayMs)
                    }
                } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
                kotlinx.coroutines.delay(if (com.aistudio.pinkproxy.fresh.BypassConfig.isCharging) 5 * 60 * 1000L else 15 * 60 * 1000L)"""

content = content.replace(find, repl).replace(find2, repl2)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RobustResolver.kt', 'w') as f:
    f.write(content)
