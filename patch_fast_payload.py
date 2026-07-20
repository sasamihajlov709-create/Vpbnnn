import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """    private suspend fun proxyStream(input: InputStream, output: OutputStream, onError: () -> Unit, host: String?, isRecv: Boolean, strategy: BypassStrategy?) {
        val buf = BypassConfig.TrafficShaper.acquireBuffer(16384)
        var successRecorded = false
        var lastActivity = System.currentTimeMillis()
        
        coroutineScope {"""

repl = """    private suspend fun proxyStream(input: InputStream, output: OutputStream, onError: () -> Unit, host: String?, isRecv: Boolean, strategy: BypassStrategy?) {
        val buf = BypassConfig.TrafficShaper.acquireBuffer(16384)
        var successRecorded = false
        var lastActivity = System.currentTimeMillis()
        var totalProcessedBytes = 0L
        
        coroutineScope {"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Failed to find init block")

find2 = """                    if (!isRecv && strategy != null && strategy != BypassStrategy.DIRECT) {"""
repl2 = """                    if (!isRecv && strategy != null && strategy != BypassStrategy.DIRECT && totalProcessedBytes < 8192) {"""

if find2 in content:
    content = content.replace(find2, repl2)
else:
    print("Failed to find condition")

find3 = """                    if (isRecv && r > 2048) BypassConfig.TrafficShaper.pace(BypassConfig.isPanicMode, r)
                }
            } catch (e: Exception) {"""
repl3 = """                    if (isRecv && r > 2048) BypassConfig.TrafficShaper.pace(BypassConfig.isPanicMode, r)
                    totalProcessedBytes += r
                }
            } catch (e: Exception) {"""

if find3 in content:
    content = content.replace(find3, repl3)
else:
    print("Failed to find totalProcessedBytes increment")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
