with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryManager.kt', 'r') as f:
    text = f.read()

import re
old_panic = """    private fun triggerPanic(reason: String) {
        if (!BypassConfig.isPanicMode) {
            Log.w("RecoveryManager", "Triggering Panic Mode: $reason")
            BypassConfig.panicOptimize()
        }
    }"""

new_panic = """    private fun triggerPanic(reason: String) {
        if (!BypassConfig.isPanicMode) {
            Log.w("RecoveryManager", "Triggering Panic Mode: $reason")
            ProxyStats.clearCensorshipHistory()
            BypassConfig.panicOptimize()
        }
    }"""

text = text.replace(old_panic, new_panic)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryManager.kt', 'w') as f:
    f.write(text)
