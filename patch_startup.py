import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'r') as f:
    text = f.read()

# Replace performDataPlaneHealthProbe call
call_replacement = '''
            // Perform Multi-Layer Data-Plane readiness check through proxy
            val diagnostic = DiagnosticManager.runFullDiagnostic()

            // 7. Now that proxy & tun2socks are fully running, start health checkers & monitors
            RuntimeCoordinator.initialize(vpnService)
            RecoveryStateMachine.start(session.recoveryScope)
            ServiceChecker.startChecking(session.controlPlaneScope, vpnService)
            healthMonitor.start(session.controlPlaneScope)

            if (diagnostic.level < DiagnosticManager.HealthLevel.L4_TCP_REACHABLE) {
                Log.w("VpnStartupCoordinator", "Data-plane probe failed (Level ${diagnostic.level}), setting state to DEGRADED.")
                VpnRuntimeState.updateState(VpnLifecycleState.DEGRADED, diagnostic.recommendation)
            } else {
                Log.i("VpnStartupCoordinator", "Data-plane probe passed (Level ${diagnostic.level})!")
                VpnRuntimeState.updateState(VpnLifecycleState.RUNNING)
                VpnRuntimeState.clearError()
            }
'''

call_pattern = re.compile(r'            // Perform Data-Plane readiness check through proxy.*?            \}', re.DOTALL)
text = call_pattern.sub(call_replacement.strip(), text, count=1)

# Remove performDataPlaneHealthProbe function
func_pattern = re.compile(r'    private suspend fun performDataPlaneHealthProbe.*?\}', re.DOTALL)
text = func_pattern.sub('', text)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'w') as f:
    f.write(text)
