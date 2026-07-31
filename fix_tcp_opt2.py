with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'r') as f:
    text = f.read()

import re
# Is there any point where we loop endlessly without yield?
if "while (true) {" in text or "while(true){" in text:
    print("Found while(true) loop")
if "while (isActive)" in text:
    print("Found while(isActive)")

