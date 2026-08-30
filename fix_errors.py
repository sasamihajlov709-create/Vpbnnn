import re

# Fix StabilityAnalyzer initialization
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StabilityAnalyzer.kt', 'r') as f:
    content = f.read()

content = content.replace("DpiAnalyzer.CensorshipFingerprint()", "DpiAnalyzer.CensorshipFingerprint(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, TransportType.TCP)")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StabilityAnalyzer.kt', 'w') as f:
    f.write(content)

# Fix PinkVpnService import
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    content = f.read()

if "import kotlinx.coroutines.flow.collectLatest" not in content:
    content = content.replace("import kotlinx.coroutines.flow.combine", "import kotlinx.coroutines.flow.combine\nimport kotlinx.coroutines.flow.collectLatest")

if "import kotlinx.coroutines.flow.collectLatest" not in content:
    content = content.replace("import kotlinx.coroutines.launch", "import kotlinx.coroutines.launch\nimport kotlinx.coroutines.flow.collectLatest")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.write(content)
