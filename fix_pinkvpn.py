import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    lines = f.readlines()

for i in range(len(lines)):
    if 'delayjava.util.concurrent.ThreadLocalRandom.current().nextLong(min((1L, (2).toLong()), max((1L, (2).toLong()) + 1L))' in lines[i]:
        lines[i] = '                                            delay(java.util.concurrent.ThreadLocalRandom.current().nextLong(1, 3))\n'
    if 'delay((BypassConfig.isPanicMode.let { if java.util.concurrent.ThreadLocalRandom.current().nextLong(min(it) 1L, (3 else 1..5 }).toLong()), max(it) 1L, (3 else 1..5 }).toLong()) + 1L))' in lines[i]:
        lines[i] = '                                        delay(BypassConfig.isPanicMode.let { if (it) java.util.concurrent.ThreadLocalRandom.current().nextLong(1, 4) else java.util.concurrent.ThreadLocalRandom.current().nextLong(1, 6) })\n'

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.writelines(lines)
