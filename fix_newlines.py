with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

import re
content = re.sub(
    r'val firstLine = header\.substringBefore\(".*?"\)\.substringBefore\(".*?"\)\.trim\(\)',
    r'val firstLine = header.substringBefore("\\r").substringBefore("\\n").trim()',
    content,
    flags=re.DOTALL
)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
