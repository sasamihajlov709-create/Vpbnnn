with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryManager.kt', 'r') as f:
    text = f.read()

import re
old_panic = """    private fun triggerPanic(reason: String) {
        val now = System.currentTimeMillis()
        if (now - lastPanicTime < 15000) return
        lastPanicTime = now"""

new_panic = """    private fun triggerPanic(reason: String) {
        val now = System.currentTimeMillis()
        if (now - lastPanicTime < 15000) return
        lastPanicTime = now
        ProxyStats.clearCensorshipHistory() // Forget old stats to allow new strategies to work without penalty"""

text = text.replace(old_panic, new_panic)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryManager.kt', 'w') as f:
    f.write(text)
