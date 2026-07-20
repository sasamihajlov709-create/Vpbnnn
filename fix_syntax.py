import re

def fix_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # for java.util.concurrent.ThreadLocalRandom.current().nextInt(i in 1, ((1..3) + 1)) -> for (i in 1..java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 4))
    content = content.replace('for java.util.concurrent.ThreadLocalRandom.current().nextInt(i in 1, ((1..3) + 1))', 'for (i in 1..java.util.concurrent.ThreadLocalRandom.current().nextInt(1, 4))')
    
    # socket.sendUrgentDatajava.util.concurrent.ThreadLocalRandom.current().nextInt((0, (255) + 1)) -> socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256))
    content = content.replace('socket.sendUrgentDatajava.util.concurrent.ThreadLocalRandom.current().nextInt((0, (255) + 1))', 'socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256))')

    # ByteArrayjava.util.concurrent.ThreadLocalRandom.current().nextInt((10, (30) + 1)) { java.util.concurrent.ThreadLocalRandom.current().nextInt(0, (255) + 1).toByte() } -> ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(10, 31)) { java.util.concurrent.ThreadLocalRandom.current().nextInt(256).toByte() }
    content = re.sub(r'ByteArrayjava\.util\.concurrent\.ThreadLocalRandom\.current\(\)\.nextInt\(\(([^,]+),\s*\(([^)]+)\)\s*\+\s*1\)\)\s*\{\s*java\.util\.concurrent\.ThreadLocalRandom\.current\(\)\.nextInt\(0,\s*\(([^)]+)\)\s*\+\s*1\)\.toByte\(\)\s*\}', r'ByteArray(java.util.concurrent.ThreadLocalRandom.current().nextInt(\1, \2 + 1)) { java.util.concurrent.ThreadLocalRandom.current().nextInt(256).toByte() }', content)

    # ... I need to see the other compile errors to fix them.
    with open(filepath, 'w') as f:
        f.write(content)

fix_file('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt')
