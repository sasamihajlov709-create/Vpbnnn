with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'r') as f:
    tcp_text = f.read()

import re
# check where we can improve TCP engine performance or logic
print(f"TcpTransportHandler size: {len(tcp_text)}")
if "kotlinx.coroutines.isActive" in tcp_text:
    print("Uses isActive.")
