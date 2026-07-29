import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    lines = f.readlines()

udp_when = []
tcp_when = []

mode = None
for i, line in enumerate(lines):
    if i + 1 == 1060:
        mode = "UDP"
    elif i + 1 == 1473:
        mode = "TCP"
    elif i + 1 == 2901:
        mode = None

    if mode and "BypassStrategy." in line and "->" in line:
        strats = re.findall(r'BypassStrategy\.([A-Z0-9_]+)', line)
        if mode == "UDP":
            udp_when.extend(strats)
        else:
            tcp_when.extend(strats)

print(f"UDP when has {len(udp_when)} strategies explicitly handled.")
print(f"TCP when has {len(tcp_when)} strategies explicitly handled.")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassTypes.kt", "r") as f:
    bt = f.read()

family_map = {}
for line in bt.splitlines():
    m = re.search(r'([A-Z0-9_]+)\(StrategyFamily\.([A-Z]+)', line)
    if m:
        family_map[m.group(1)] = m.group(2)

print("\n--- UDP Families missing in UDP when ---")
for s, f in sorted(family_map.items()):
    if f in ["UDP", "QUIC", "DNS"] and s not in udp_when:
        print(f"  {s} ({f}) -> in TCP: {s in tcp_when}")

print("\n--- TCP/TLS/HTTP/FRAGMENTATION/TIMING Families missing in TCP when ---")
for s, f in sorted(family_map.items()):
    if f in ["TCP", "TLS", "HTTP", "FRAGMENTATION", "TIMING", "ADAPTIVE"] and s not in tcp_when:
        print(f"  {s} ({f}) -> in UDP: {s in udp_when}")

