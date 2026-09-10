import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'r') as f:
    text = f.read()

replacement = '''
            if (diagnostic.level < DiagnosticManager.HealthLevel.L4_TCP_REACHABLE) {
                Log.w("VpnStartupCoordinator", "Data-plane probe failed (Level ${diagnostic.level}), setting state to DEGRADED.")
                VpnRuntimeState.updateState(VpnLifecycleState.DEGRADED, diagnostic.recommendation)
            } else {
                Log.i("VpnStartupCoordinator", "Data-plane probe passed (Level ${diagnostic.level})!")
                VpnRuntimeState.updateState(VpnLifecycleState.RUNNING)
                VpnRuntimeState.clearError()
            }
'''

pattern = re.compile(r'            if \(diagnostic\.level < DiagnosticManager\.HealthLevel\.L4_TCP_REACHABLE\) \{.*?\} else \{.*?\} else \{.*?\}', re.DOTALL)
text = pattern.sub(replacement.strip(), text)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'w') as f:
    f.write(text)
