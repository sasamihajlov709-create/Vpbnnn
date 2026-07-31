import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyStats.kt', 'r') as f:
    text = f.read()
    
# Let's see if we can optimize the buffer pool
if "java.util.concurrent.ConcurrentLinkedQueue" in text:
    print("Uses ConcurrentLinkedQueue")
if "ByteArray" in text:
    print("Uses ByteArray")
