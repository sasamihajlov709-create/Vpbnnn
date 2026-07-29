import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassTypes.kt", "r") as f:
    bt_code = f.read()

family_map = {}
for line in bt_code.splitlines():
    m = re.search(r'([A-Z0-9_]+)\(StrategyFamily\.([A-Z]+)', line)
    if m:
        family_map[m.group(1)] = m.group(2)

tcp_strats = set(re.findall(r'BypassStrategy\.([A-Z0-9_]+)', code))

print("Strategies missing from BypassConfig.kt entirely:")
for strat, fam in sorted(family_map.items()):
    if strat not in tcp_strats:
        print(f"  [MISSING] {strat} ({fam})")

