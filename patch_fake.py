with open('app/src/main/java/com/aistudio/pinkproxy/fresh/FakePacketHelper.kt', 'r') as f:
    content = f.read()

import re
content = re.sub(
    r'object FakePacketHelper \{',
    r'object FakePacketHelper {\n    private val cachedQuicInitial = buildQuicInitial()\n    private var cacheTime = System.currentTimeMillis()\n    \n    fun getCachedQuicInitial(): ByteArray {\n        if (System.currentTimeMillis() - cacheTime > 30000) {\n            cachedQuicInitial = buildQuicInitial()\n            cacheTime = System.currentTimeMillis()\n        }\n        return cachedQuicInitial\n    }',
    content
)

content = content.replace('FakePacketHelper.buildQuicInitial()', 'FakePacketHelper.getCachedQuicInitial()')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/FakePacketHelper.kt', 'w') as f:
    f.write(content)
