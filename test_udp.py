with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt', 'r') as f:
    text = f.read()

import re
print("Length:", len(text))
if "while (isActive)" in text:
    print("Found while(isActive)")
