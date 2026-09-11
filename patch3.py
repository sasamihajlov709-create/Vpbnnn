import re

# TUN_FALLBACK and UI 
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnState.kt', 'r') as f:
    text = f.read()
text = text.replace('ERROR\n}', 'ERROR,\n    TUN_FALLBACK\n}')
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnState.kt', 'w') as f:
    f.write(text)

for file_path, old_str, new_str in [
    ('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/PinkProxyApp.kt', 'VpnLifecycleState.RUNNING -> StatusBadge', 'VpnLifecycleState.RUNNING, VpnLifecycleState.TUN_FALLBACK -> StatusBadge'),
    ('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/PinkProxyApp.kt', 'vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING', 'vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING || vpnState == VpnLifecycleState.TUN_FALLBACK'),
    ('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/MetricsComponents.kt', 'state == VpnLifecycleState.RUNNING || state == VpnLifecycleState.RECOVERING', 'state == VpnLifecycleState.RUNNING || state == VpnLifecycleState.RECOVERING || state == VpnLifecycleState.TUN_FALLBACK'),
    ('app/src/main/java/com/aistudio/pinkproxy/fresh/ui/components/PowerButton.kt', 'vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING', 'vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING || vpnState == VpnLifecycleState.TUN_FALLBACK'),
    ('app/src/main/java/com/aistudio/pinkproxy/fresh/MainActivity.kt', 'vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING', 'vpnState == VpnLifecycleState.RUNNING || vpnState == VpnLifecycleState.RECOVERING || vpnState == VpnLifecycleState.TUN_FALLBACK')
]:
    with open(file_path, 'r') as f:
        content = f.read()
    with open(file_path, 'w') as f:
        f.write(content.replace(old_str, new_str))

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'r') as f:
    text = f.read()
text = text.replace('VpnRuntimeState.updateState(VpnLifecycleState.STARTING, "Fallback tunnel mode activated (IPv4-only)")', 'VpnRuntimeState.updateState(VpnLifecycleState.TUN_FALLBACK, "Fallback tunnel mode activated (IPv4-only)")')
rep1 = '''
            var isTunFallback = false
            val pfd = try {
                vpnTunnelManager.establish(
'''
text = re.sub(r'            val pfd = try \{[^v]+vpnTunnelManager\.establish\(', rep1.strip(), text, count=1)
rep2 = '''
                isTunFallback = true
                VpnRuntimeState.updateState(VpnLifecycleState.TUN_FALLBACK, "Fallback tunnel mode activated (IPv4-only)")
'''
text = re.sub(r'                VpnRuntimeState\.updateState\(VpnLifecycleState\.TUN_FALLBACK, "Fallback tunnel mode activated \(IPv4-only\)"\)', rep2.strip(), text)
rep3 = '''
            if (diagnostic.level < DiagnosticManager.HealthLevel.L4_TCP_REACHABLE) {
                Log.w("VpnStartupCoordinator", "Data-plane probe failed (Level ${diagnostic.level}), setting state to DEGRADED.")
                VpnRuntimeState.updateState(VpnLifecycleState.DEGRADED, diagnostic.recommendation)
            } else {
                Log.i("VpnStartupCoordinator", "Data-plane probe passed (Level ${diagnostic.level})!")
                VpnRuntimeState.updateState(if (isTunFallback) VpnLifecycleState.TUN_FALLBACK else VpnLifecycleState.RUNNING)
                VpnRuntimeState.clearError()
            }
'''
text = re.sub(r'            if \(diagnostic\.level < DiagnosticManager\.HealthLevel\.L4_TCP_REACHABLE\) \{.*?\n            \}', rep3.strip(), text, flags=re.DOTALL)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'w') as f:
    f.write(text)

