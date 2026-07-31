with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

import re
old_shaper = """            if (errorCounter > 8) {
                ProxyStats.updateCongestionWindow(-5)
                // Heuristic: continuous errors might be MTU issues
                if (errorCounter > 20) {
                    val currentMtu = _currentMtu.value
                    if (currentMtu > 1200) {
                        _currentMtu.value = currentMtu - 50
                        ProxyStats.logRecovery("MTU Auto-tuning: $currentMtu -> ${_currentMtu.value} due to persistent errors.")
                        RecoveryManager.handleEvent(RecoveryEvent.TUNNEL_STALL, "MTU Tuned")
                    }
                }
                errorCounter = 0
            }"""

new_shaper = """            if (errorCounter > 8) {
                ProxyStats.updateCongestionWindow(-5)
            }
            if (errorCounter > 20) {
                val currentMtu = _currentMtu.value
                if (currentMtu > 1200) {
                    _currentMtu.value = currentMtu - 50
                    ProxyStats.logRecovery("MTU Auto-tuning: $currentMtu -> ${_currentMtu.value} due to persistent errors.")
                    RecoveryManager.handleEvent(RecoveryEvent.TUNNEL_STALL, "MTU Tuned")
                }
                errorCounter = 0
            }"""

text = text.replace(old_shaper, new_shaper)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'w') as f:
    f.write(text)
