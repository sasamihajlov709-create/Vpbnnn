import subprocess
import re
import sys

# 1. Get warnings
result = subprocess.run(["gradle", ":app:assembleDebug", "--rerun-tasks"], capture_output=True, text=True)
output = result.stdout + result.stderr

warnings = []
for line in output.split('\n'):
    if "Duplicate branch condition in 'when'" in line and "BypassConfig.kt" in line:
        # e.g. w: file:///app/applet/app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt:1299:13
        m = re.search(r'BypassConfig\.kt:(\d+):', line)
        if m:
            warnings.append(int(m.group(1)))

warnings = sorted(list(set(warnings)), reverse=True)
print("Found duplicate branches at lines:", warnings)

if not warnings:
    sys.exit(0)

# 2. Parse file and remove branches
file_path = "app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt"
with open(file_path, "r") as f:
    lines = f.readlines()

for line_num in warnings:
    idx = line_num - 1
    # The branch starts at idx
    # We need to find where it ends.
    # It usually looks like `BypassStrategy.SOME_NAME -> {`
    # We count braces to find the end.
    
    start_idx = idx
    # Sometimes the warning points to the annotation or something, but usually it points to the `BypassStrategy.XXX`
    if "->" not in lines[start_idx]:
        # look forward a bit
        for offset in range(5):
            if "->" in lines[start_idx + offset]:
                start_idx = start_idx + offset
                break

    line_str = lines[start_idx]
    if "{" in line_str:
        braces = 1
        end_idx = start_idx + 1
        while end_idx < len(lines):
            braces += lines[end_idx].count("{")
            braces -= lines[end_idx].count("}")
            if braces == 0:
                break
            end_idx += 1
    else:
        # One liner without braces?
        end_idx = start_idx
        
    print(f"Removing duplicate branch from {start_idx+1} to {end_idx+1}: {lines[start_idx].strip()}")
    # Delete lines
    del lines[start_idx:end_idx+1]

with open(file_path, "w") as f:
    f.writelines(lines)

print("Done fixing duplicates!")
