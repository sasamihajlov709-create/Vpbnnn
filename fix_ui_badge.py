import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/MainActivity.kt', 'r') as f:
    content = f.read()

# Check if SOCKS5 Badge exists
if 'SOCKS5: 127.0.0.1:18080' in content:
    print("Badge already exists.")
else:
    print("Badge missing.")

