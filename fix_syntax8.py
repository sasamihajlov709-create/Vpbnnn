with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()

import re

lines = text.splitlines()

# Search for the string "BypassStrategy.TCP_ACK_SKEW -> {"
# What is the full text of that line?
print(repr(lines[2905]))

