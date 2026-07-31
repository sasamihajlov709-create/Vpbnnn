import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'r') as f:
    text = f.read()

# See how we are forwarding data in the main loop
lines = text.splitlines()

# We can improve the buffer allocation or the traffic shaping
print("ProxyStats available buffers logic:")
for line in lines:
    if "ProxyStats.release" in line:
        print(line.strip())
