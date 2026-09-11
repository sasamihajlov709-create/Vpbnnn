with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'r') as f:
    text = f.read()

text = text.replace('VpnRuntimeState.updateState(VpnLifecycleState.RUNNING)', 'VpnRuntimeState.updateState(if (isTunFallback) VpnLifecycleState.TUN_FALLBACK else VpnLifecycleState.RUNNING)')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'w') as f:
    f.write(text)
