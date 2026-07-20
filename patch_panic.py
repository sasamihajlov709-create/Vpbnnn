import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """        if (lastResults.size >= 10 && failures.toFloat() / lastResults.size > 0.6f) {
            if (!isPanicMode) {
                panicOptimize()
                ProxyStats.logRecovery("AUTO-HEAL: High failure rate detected (${failures}/${lastResults.size}). Panic mode engaged.")
            }
        }"""

repl = """        if (lastResults.size >= 10 && failures.toFloat() / lastResults.size > 0.6f) {
            if (!isPanicMode) {
                panicOptimize()
                ProxyStats.logRecovery("AUTO-HEAL: High failure rate detected (${failures}/${lastResults.size}). Panic mode engaged.")
                if (isAutoTuning) {
                    val context = ServiceChecker.appContext
                    if (context != null) {
                        ProxyStats.logRecovery("AUTO-HEAL: Triggering autopilot probe to find a better strategy.")
                        ServiceChecker.runActiveProbing(context)
                    }
                }
            }
        }"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Could not find block")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
