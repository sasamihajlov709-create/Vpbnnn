with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    lines = f.readlines()

for i in range(len(lines)):
    if 'BypassConfig.shadowProbejava.util.concurrent.ThreadLocalRandom.current().nextLong(min(target)' in lines[i]:
        lines[i] = '                    BypassConfig.shadowProbe(target)\n'
    if 'delay(60000 + (0L, (60000).toLong()), max(target)' in lines[i]:
        lines[i] = '                delay(60000 + java.util.concurrent.ThreadLocalRandom.current().nextLong(0, 60001))\n'
    if 'isPanic -> java.util.concurrent.ThreadLocalRandom.current().nextLongjava.util.concurrent.ThreadLocalRandom.current().nextLong(min(5, 21)' in lines[i]:
        lines[i] = '                isPanic -> java.util.concurrent.ThreadLocalRandom.current().nextLong(5, 21)\n'
    if 'else -> (1L, (5).toLong()), max(5, 21)' in lines[i]:
        lines[i] = '                else -> java.util.concurrent.ThreadLocalRandom.current().nextLong(1, 6)\n'
    if 'else -> (1L, (5).toLong()) + 1L)' in lines[i]:
        lines[i] = '' # Delete duplicate else line

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.writelines(lines)
