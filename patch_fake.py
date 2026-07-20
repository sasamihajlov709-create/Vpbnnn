with open('app/src/main/java/com/aistudio/pinkproxy/fresh/FakePacketHelper.kt', 'r') as f:
    content = f.read()

import re
content = content.replace('private val random = java.util.Random()', '')
content = content.replace('random.nextInt', 'java.util.concurrent.ThreadLocalRandom.current().nextInt')
content = content.replace('random.nextLong', 'java.util.concurrent.ThreadLocalRandom.current().nextLong')
content = content.replace('random.nextDouble', 'java.util.concurrent.ThreadLocalRandom.current().nextDouble')
content = content.replace('random.nextBoolean', 'java.util.concurrent.ThreadLocalRandom.current().nextBoolean')
content = content.replace('random.nextBytes', 'java.util.concurrent.ThreadLocalRandom.current().nextBytes')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/FakePacketHelper.kt', 'w') as f:
    f.write(content)
