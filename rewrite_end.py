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
            
            return@withContext true

        } catch (e: Exception) {
            if (e is CancellationException) throw e
            Log.e("VpnStartupCoordinator", "Error starting VPN", e)
            VpnRuntimeState.updateState(VpnLifecycleState.FAILED, "Critical startup error: ${e.localizedMessage}")
            return@withContext false
        }
    }
'''

pattern = re.compile(r'if \(diagnostic\.level < DiagnosticManager\.HealthLevel\.L4_TCP_REACHABLE\) \{.*?\n\}', re.DOTALL)
text = pattern.sub(replacement.strip() + '\n', text)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'w') as f:
    f.write(text)
