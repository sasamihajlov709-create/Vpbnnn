import re
import sys

def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    # Replace (a..b).random().toLong()
    content = re.sub(r'\(([^.]+)\.\.([^)]+)\)\.random\(\)\.toLong\(\)', r'java.util.concurrent.ThreadLocalRandom.current().nextLong(min(\1L, (\2).toLong()), max(\1L, (\2).toLong()) + 1L)', content)
    # Simple (a..b).random()
    content = re.sub(r'\(([^.]+)\.\.([^)]+)\)\.random\(\)', r'java.util.concurrent.ThreadLocalRandom.current().nextInt(\1, (\2) + 1)', content)
    # Replace (a until b).random()
    content = re.sub(r'\(([^.]+)\s+until\s+([^)]+)\)\.random\(\)', r'java.util.concurrent.ThreadLocalRandom.current().nextInt(\1, \2)', content)
    # Replace Math.random()
    content = re.sub(r'Math\.random\(\)', r'java.util.concurrent.ThreadLocalRandom.current().nextDouble()', content)

    with open(filepath, 'w') as f:
        f.write(content)

process_file('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt')
process_file('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt')
process_file('app/src/main/java/com/aistudio/pinkproxy/fresh/FakePacketHelper.kt')
print("Done")
