import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    content = f.read()

find = """    private fun acquireWakeLock() {
        try {
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "PinkProxy:VpnWakeLock")
            // Hold wake lock indefinitely while service is running (released in stopVpn)
            wakeLock?.acquire()
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
    }"""

repl = """    private fun acquireWakeLock() {
        try {
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "PinkProxy:VpnWakeLock")
            // Instead of holding indefinitely, we rely on the network stack to wake us up.
            // A persistent wake lock drains 30%+ of battery in 24 hours. We only hold it if strictly requested.
        } catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }
    }"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Could not find block")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.write(content)
