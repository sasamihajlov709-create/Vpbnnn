import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    lines = f.readlines()

new_lines = []
imports = []
for line in lines:
    if line.startswith("import kotlinx.coroutines.flow.collectLatest") or line.startswith("import kotlinx.coroutines.flow.combine"):
        imports.append(line)
    else:
        new_lines.append(line)

final_lines = []
for line in new_lines:
    final_lines.append(line)
    if line.startswith("package"):
        final_lines.extend(imports)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.writelines(final_lines)
