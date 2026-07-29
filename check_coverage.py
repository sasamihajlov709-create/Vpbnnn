import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassTypes.kt", "r") as f:
    bt_code = f.read()

# Extract all BypassStrategy values
match = re.search(r'enum class BypassStrategy[^{]*\{([^}]+)\}', bt_code, re.DOTALL)
if match:
    enum_content = match.group(1)
    # Find all enum entry names
    strategies = set(re.findall(r'([A-Z0-9_]+)\(', enum_content))
    strategies.add("DIRECT")
else:
    print("Could not find BypassStrategy enum")
    exit(1)

print(f"Total strategies defined in enum: {len(strategies)}")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    bc_code = f.read()

# Find all strategies mentioned in applyBypass and applyUdpBypass
handled_tcp = set()
handled_udp = set()

# Simple regex search for BypassStrategy.NAME in BypassConfig
for strat in strategies:
    if f"BypassStrategy.{strat}" in bc_code:
        handled_tcp.add(strat)

unhandled = strategies - handled_tcp
print(f"Strategies missing completely in BypassConfig.kt: {len(unhandled)}")
if unhandled:
    print("Missing:", sorted(list(unhandled)))

