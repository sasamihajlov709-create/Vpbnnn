import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/PinkProxyApp.kt', 'r') as f:
    content = f.read()

target = """    val isProbing by ServiceChecker.isProbingState.collectAsStateWithLifecycle(initialValue = false)"""

replacement = """    val isServiceProbing by ServiceChecker.isProbingState.collectAsStateWithLifecycle(initialValue = false)
    val isEngineProbing by VpnRuntimeState.isEngineProbing.collectAsStateWithLifecycle(initialValue = false)
    val isProbing = isServiceProbing || isEngineProbing"""

content = content.replace(target, replacement)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/PinkProxyApp.kt', 'w') as f:
    f.write(content)

