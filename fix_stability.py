import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StabilityAnalyzer.kt', 'r') as f:
    content = f.read()

# I will add a MutableStateFlow for fingerprint
content = content.replace(
    "val _censorshipIntensity = MutableStateFlow(0)",
    "val _censorshipIntensity = MutableStateFlow(0)\n    private val _fingerprint = MutableStateFlow(DpiAnalyzer.CensorshipFingerprint())\n    val fingerprint: StateFlow<DpiAnalyzer.CensorshipFingerprint> = _fingerprint.asStateFlow()"
)

# I will update it when analyzing
content = content.replace(
    "_censorshipIntensity.value = tcpIntensity",
    "_censorshipIntensity.value = tcpIntensity\n                _fingerprint.value = DpiAnalyzer.getCensorshipFingerprint(TransportType.TCP)"
)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StabilityAnalyzer.kt', 'w') as f:
    f.write(content)
