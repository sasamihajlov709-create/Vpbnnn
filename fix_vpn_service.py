import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    content = f.read()

# Fix the syntax error at line 105-106
content = content.replace("    private var isStopping = false\n        startDynamicNotification()", "    private var isStopping = false")
content = content.replace("isVpnRunning()", "_isRunning.value")

# The replacement I intended earlier for startVpnInternal and stopVpnInternal
# Look for:
# private suspend fun startVpnInternal() = withContext(ProxyDispatcher.io) {
#         if (_isRunning.value) return@withContext
#         isStopping = false
# I accidentally replaced "isStopping = false" everywhere earlier. I need to fix it carefully.

content = content.replace(
'''    private suspend fun startVpnInternal() = withContext(ProxyDispatcher.io) {
        if (_isRunning.value) return@withContext
        isStopping = false''',
'''    private suspend fun startVpnInternal() = withContext(ProxyDispatcher.io) {
        if (_isRunning.value) return@withContext
        isStopping = false
        startDynamicNotification()'''
)

content = content.replace(
'''    private suspend fun stopVpnInternal() = withContext(ProxyDispatcher.io) {
        isStopping = true''',
'''    private suspend fun stopVpnInternal() = withContext(ProxyDispatcher.io) {
        isStopping = true
        stopDynamicNotification()'''
)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.write(content)
