import os

path = '/app/applet/app/src/main/java/com/aistudio/pinkproxy/fresh/HttpStrategyHandler.kt'
with open(path, 'r') as f:
    content = f.read()

# Fix HTTP_FRAGMENT
content = content.replace(
    """        if (strategy == BypassStrategy.HTTP_FRAGMENT) {
            var pos = 0
            while (pos < length) {
                output.write(data, pos, 1)""",
    """        if (strategy == BypassStrategy.HTTP_FRAGMENT) {
            var pos = 0
            while (pos < length) {
                val sz = if (length > 200) rnd.nextInt(4, 16) else 1
                val chunk = sz.coerceAtMost(length - pos)
                output.write(data, pos, chunk)"""
)
content = content.replace(
    """                output.flush()
                pos += 1""",
    """                output.flush()
                pos += chunk"""
)

# Also fix TCP_REARRANGE_CHUNKS limits
content = content.replace(
    'if (strategy == BypassStrategy.TCP_REARRANGE_CHUNKS) {',
    'if (strategy == BypassStrategy.TCP_REARRANGE_CHUNKS) { // Deprecated/Not in enum, kept for legacy logic'
)

with open(path, 'w') as f:
    f.write(content)
