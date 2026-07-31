with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

import re
print("Length:", len(text))
print("Uses of yield:", text.count('yield()'))
print("Uses of delay(1):", text.count('delay(1)'))
