with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpAssociationTable.kt', 'r') as f:
    text = f.read()

import re
text = re.sub(r'fun touchSession\(key: UdpSessionKey.*?\n    \}\n        if \(receivedBytes > 0\) \{.*?\n    \}',
'''    fun touchSession(key: UdpSessionKey, sentBytes: Long = 0L, receivedBytes: Long = 0L) {
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
    }''', text, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpAssociationTable.kt', 'w') as f:
    f.write(text)
