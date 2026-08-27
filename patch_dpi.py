import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "r") as f:
    content = f.read()

# For each case:
#                RuntimeCoordinator.applyStrategyTransition(selected, TransportType.TCP, "Active TCP Reset DPI detected")
#                if (targetHost != null) {
#                        RuntimeCoordinator.requestGlobalStrategyRotation(transport, "DPI Signal Escalation", HostClassifier.classify(targetHost), host = targetHost)
#                    }

def replace_block(match):
    # This match will capture the applyStrategyTransition and the if block.
    # We want to replace it with:
    # if (targetHost != null) { requestGlobalStrategyRotation... } else { applyStrategyTransition... }
    apply_stmt = match.group(1)
    return f"""if (targetHost != null) {{
                    RuntimeCoordinator.requestGlobalStrategyRotation(transport, "DPI Signal Escalation", category, host = targetHost)
                }} else {{
                    {apply_stmt.strip()}
                }}"""

content = re.sub(
    r'(RuntimeCoordinator\.applyStrategyTransition\([^)]+\))\s+if\s*\(targetHost\s*!=\s*null\)\s*\{\s*RuntimeCoordinator\.requestGlobalStrategyRotation[^}]+\}',
    replace_block,
    content
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "w") as f:
    f.write(content)

