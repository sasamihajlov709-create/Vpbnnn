import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt', 'r') as f:
    text = f.read()

# Are we using a lot of allocations in the while loop?
lines = text.splitlines()
for i in [286, 307, 345, 485]:
    # Look at the next few lines
    print(f"--- Loop near {i} ---")
    for j in range(i-2, i+10):
        print(lines[j])

