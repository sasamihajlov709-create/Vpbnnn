with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DnsOptimizer.kt', 'r') as f:
    text = f.read()

import re
# check performance of DNS resolution, any blocking calls?
if "java.net.InetAddress.getAllByName" in text:
    print("Uses blocking InetAddress inside coroutines")
