with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    content = f.read()

content = content.replace('ByteArrayjava.util.concurrent.ThreadLocalRandom.current().nextInt((4, (16) + 1))', 'ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(4, 17))')
content = content.replace('FakePacketHelper.buildQuicInitialjava.util.concurrent.ThreadLocalRandom.current().nextInt() else ByteArray((8, (32) + 1))', 'FakePacketHelper.buildQuicInitial() else ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(8, 33))')
content = content.replace('FakePacketHelper.buildQuicInitialjava.util.concurrent.ThreadLocalRandom.current().nextInt() else ByteArray((4, (32) + 1))', 'FakePacketHelper.buildQuicInitial() else ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(4, 33))')
content = content.replace('java.util.concurrent.ThreadLocalRandom.current().nextInt(0, (255) + 1)', 'java.util.concurrent.ThreadLocalRandom.current().nextInt(256)')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.write(content)
