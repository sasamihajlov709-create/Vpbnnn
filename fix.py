import re

# Fix PinkVpnService
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    text = f.read()
text = text.replace('private const val PROXY_PORT', 'internal const val PROXY_PORT')
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.write(text)

# Fix VpnStartupCoordinator
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'r') as f:
    text = f.read()

text = re.sub(r'\} else \{\n                Log\.i\("VpnStartupCoordinator", "Data-plane probe passed!"\)\n                VpnRuntimeState\.updateState\(VpnLifecycleState\.RUNNING\)\n                VpnRuntimeState\.clearError\(\)\n            \}', '', text)
text = re.sub(r'            // SOCKS5 Auth.*\} catch \(e: Exception\) \{\n            false\n        \}\n    \}\n\}', '}\n', text, flags=re.DOTALL)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'w') as f:
    f.write(text)

# Fix DiagnosticManager
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DiagnosticManager.kt', 'r') as f:
    text = f.read()

text = text.replace('out.write("GET / HTTP/1.1\\nHost: 1.1.1.1\\nConnection: close\\n\\n".toByteArray())', 'out.write("GET / HTTP/1.1\\r\\nHost: 1.1.1.1\\r\\nConnection: close\\r\\n\\r\\n".toByteArray())')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DiagnosticManager.kt', 'w') as f:
    f.write(text)
