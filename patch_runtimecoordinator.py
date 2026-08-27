import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "r") as f:
    text = f.read()

replacement = """        if (host == null) {
            BypassConfig.applyInternalStrategy(best)
            VpnRuntimeState.updateStrategy(best.name, DpiStrategySelector.getSelectionReasoning(best))
            ProxyStats.logRecovery("Global Strategy rotated for $transport ($category): ${best.name} ($reason)")
        } else {
            FlowStrategyOverrideStore.putOverride(host, transport, profileId, best, reason)
            ProxyStats.logRecovery("Flow-level Strategy rotated for host=$host ($transport): ${best.name} ($reason)")
        }"""

text = re.sub(r'        if \(host == null\) \{.*?ProxyStats\.logRecovery\("Flow-level Strategy rotated for host=\$host \(\$transport\): \$\{best\.name\} \(\$reason\)"\)\n        \}', replacement, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RuntimeCoordinator.kt", "w") as f:
    f.write(text)
