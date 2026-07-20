import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    content = f.read()

find = """                        if (lowConnectivityCount >= 3) { // 1.5 minutes of low connectivity
                            ProxyStats.logRecovery("AUTO-HEAL: Performance drop. Rotating Strategy...")
                            BypassConfig.rotateGlobalStrategy()
                            restartProxyServer("Performance Optimization")
                            RobustResolver.clearCache()
                            lowConnectivityCount = 0
                        }"""

repl = """                        if (lowConnectivityCount >= 3) { // 1.5 minutes of low connectivity
                            ProxyStats.logRecovery("AUTO-HEAL: Persistent performance drop. Triggering Deep Probe...")
                            ServiceChecker.runActiveProbing(this@PinkVpnService)
                            RobustResolver.clearCache()
                            lowConnectivityCount = 0
                        }"""

content = content.replace(find, repl)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.write(content)
