import os

path = '/app/applet/app/src/main/java/com/aistudio/pinkproxy/fresh/TcpBasicStrategyHandler.kt'
with open(path, 'r') as f:
    content = f.read()

# Fix TCP_TIMING_CHAOS limits to be sane
content = content.replace(
    """            BypassStrategy.TCP_TIMING_CHAOS -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(1, 5).coerceAtMost(length - pos)""",
    """            BypassStrategy.TCP_TIMING_CHAOS -> {
                var pos = 0
                val minSz = if (length > 100) 16 else 1
                val maxSz = if (length > 100) 64 else 5
                while (pos < length) {
                    val sz = rnd.nextInt(minSz, maxSz).coerceAtMost(length - pos)"""
)

# Fix TCP_FOOL_DPI to check isFirstPacket
content = content.replace(
    """            BypassStrategy.TCP_FOOL_DPI -> {
                val fake = FakePacketHelper.buildFakeHttpRequest("decoy.org")""",
    """            BypassStrategy.TCP_FOOL_DPI -> {
                if (!context.isFirstPacket) {
                    output.write(data, 0, length)
                    output.flush()
                    return
                }
                val fake = FakePacketHelper.buildFakeHttpRequest("decoy.org")"""
)

# Fix TCP_TLS_SESSION_DESYNC to check isFirstPacket
content = content.replace(
    """            BypassStrategy.TCP_TLS_SESSION_DESYNC -> {
                val fake = FakePacketHelper.buildRealisticTlsHello("decoy.internal")""",
    """            BypassStrategy.TCP_TLS_SESSION_DESYNC -> {
                if (!context.isFirstPacket) {
                    output.write(data, 0, length)
                    output.flush()
                    return
                }
                val fake = FakePacketHelper.buildRealisticTlsHello("decoy.internal")"""
)

# Fix TCP_SMALL_CHUNKS limits
content = content.replace(
    """            BypassStrategy.TCP_SMALL_CHUNKS, BypassStrategy.TCP_RANDOM_PADDING -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(4, 12).coerceAtMost(length - pos)""",
    """            BypassStrategy.TCP_SMALL_CHUNKS, BypassStrategy.TCP_RANDOM_PADDING -> {
                var pos = 0
                val minSz = if (length > 200) 16 else 4
                val maxSz = if (length > 200) 48 else 12
                while (pos < length) {
                    val sz = rnd.nextInt(minSz, maxSz).coerceAtMost(length - pos)"""
)

# Fix TCP_SACK_FAKE limits
content = content.replace(
    """            BypassStrategy.TCP_SACK_FAKE, BypassStrategy.TCP_SACK_PANIC, BypassStrategy.TCP_SACK_SKEW -> {
                var pos = 0
                while (pos < length) {
                    val sz = rnd.nextInt(10, 30).coerceAtMost(length - pos)""",
    """            BypassStrategy.TCP_SACK_FAKE, BypassStrategy.TCP_SACK_PANIC, BypassStrategy.TCP_SACK_SKEW -> {
                var pos = 0
                val minSz = if (length > 300) 32 else 10
                val maxSz = if (length > 300) 128 else 30
                while (pos < length) {
                    val sz = rnd.nextInt(minSz, maxSz).coerceAtMost(length - pos)"""
)

with open(path, 'w') as f:
    f.write(content)
