with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

import re
content = content.replace('private val random = java.util.Random()', '')
content = content.replace('random.nextInt', 'java.util.concurrent.ThreadLocalRandom.current().nextInt')
content = content.replace('random.nextLong', 'java.util.concurrent.ThreadLocalRandom.current().nextLong')
content = content.replace('random.nextDouble', 'java.util.concurrent.ThreadLocalRandom.current().nextDouble')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
