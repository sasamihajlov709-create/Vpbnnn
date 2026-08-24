import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt", "r") as f:
    content = f.read()

content = content.replace("BypassConfig.currentMtu.value", "BypassConfig.getMtuForTransport(TransportType.TCP)")
content = content.replace("BypassConfig.currentMtu.collect { newMtu ->", "BypassConfig.isPanicModeFlow.collect { _ ->\n                val newMtu = BypassConfig.getMtuForTransport(TransportType.TCP)")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt", "w") as f:
    f.write(content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "r") as f:
    content = f.read()

content = content.replace("BypassConfig.currentMtu.value", "BypassConfig.getMtuForTransport(TransportType.TCP)")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/RecoveryStateMachine.kt", "w") as f:
    f.write(content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TtlHelper.kt", "r") as f:
    content = f.read()

content = content.replace("BypassConfig.currentMtu.value", "BypassConfig.getMtuForTransport(TransportType.TCP)")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TtlHelper.kt", "w") as f:
    f.write(content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    content = f.read()

content = content.replace("val isPanicModeFlow: StateFlow<Boolean> = _isPanicMode.asStateFlow()", "val isPanicModeFlow: StateFlow<Boolean> = _isPanicMode.asStateFlow()\n    fun setPanicMode(enabled: Boolean) { _isPanicMode.value = enabled }")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(content)

