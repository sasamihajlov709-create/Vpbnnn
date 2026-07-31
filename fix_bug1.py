with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    text = f.read()

import re
text = text.replace("val activeCount = 2000 - activeConnectionSemaphore.availablePermits()",
"val activeCount = 5000 - activeConnectionSemaphore.availablePermits()")
text = text.replace("if (activeCount > 1800) {", "if (activeCount > 4800) {")
text = text.replace("activeConnectionSemaphore.release(2000 - activeConnectionSemaphore.availablePermits())",
"activeConnectionSemaphore.release(5000 - activeConnectionSemaphore.availablePermits())")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(text)
