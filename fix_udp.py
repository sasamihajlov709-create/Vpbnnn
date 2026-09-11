import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpAssociationTable.kt', 'r') as f:
    text = f.read()

text = text.replace('import java.util.concurrent.ConcurrentHashMap', 'import java.util.concurrent.ConcurrentHashMap\nimport java.util.concurrent.atomic.AtomicLong')

# Fix UdpAssociation properties
rep_props = """
    val key: UdpSessionKey,
    val socksSessionId: String = "",
    val createdAt: Long = System.currentTimeMillis(),
    @Volatile var strategy: BypassStrategy
) {
    val lastActivity = AtomicLong(System.currentTimeMillis())
    val packetsSent = AtomicLong(0L)
    val packetsReceived = AtomicLong(0L)
    val bytesSent = AtomicLong(0L)
    val bytesReceived = AtomicLong(0L)
"""
text = re.sub(r'    val key: UdpSessionKey,.*?\@Volatile var strategy: BypassStrategy\n\) \{', rep_props.strip() + ' {', text, flags=re.DOTALL)

# Fix creation
text = text.replace('UdpAssociation(key = it, socksSessionId = sessionId, strategy = strategy)', 'UdpAssociation(key = it, socksSessionId = sessionId, strategy = strategy)')
text = text.replace('it.lastActivity = System.currentTimeMillis()', 'it.lastActivity.set(System.currentTimeMillis())')

# Fix touchSession
rep_touch = """
    fun touchSession(key: UdpSessionKey, sentBytes: Long = 0L, receivedBytes: Long = 0L) {
        val entry = sessions[key] ?: return
        entry.lastActivity.set(System.currentTimeMillis())
        if (sentBytes > 0) {
            entry.packetsSent.incrementAndGet()
            entry.bytesSent.addAndGet(sentBytes)
        }
        if (receivedBytes > 0) {
            entry.packetsReceived.incrementAndGet()
            entry.bytesReceived.addAndGet(receivedBytes)
        }
    }
"""
text = re.sub(r'    fun touchSession\(.*?\}', rep_touch.strip(), text, flags=re.DOTALL)

text = text.replace('entry.value.lastActivity > maxIdleDurationMs', 'entry.value.lastActivity.get() > maxIdleDurationMs')
text = text.replace('now - entry.value.lastActivity > maxIdleDurationMs', 'now - entry.value.lastActivity.get() > maxIdleDurationMs')


with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpAssociationTable.kt', 'w') as f:
    f.write(text)
