with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt', 'r') as f:
    text = f.read()

import re

old = """    private val coreCount = Runtime.getRuntime().availableProcessors()
    private val poolSize = (coreCount * 4).coerceIn(16, 64)
    val io = Executors.newFixedThreadPool(poolSize) { r ->"""

new = """    val io = Executors.newCachedThreadPool { r ->"""

text = re.sub(r'private val coreCount.*?(?=val io)', '', text, flags=re.DOTALL)
text = text.replace('Executors.newFixedThreadPool(poolSize)', 'Executors.newCachedThreadPool()')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt', 'w') as f:
    f.write(text)
print("done")
