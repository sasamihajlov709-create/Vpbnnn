with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassTypes.kt', 'r') as f:
    text = f.read()

import re

# Add clearCensorshipHistory method
text = text.replace("    fun recordCensorshipEvent(isFailure: Boolean) {",
"    fun clearCensorshipHistory() {\n        _censorshipIntensity.value = 0\n    }\n\n    fun recordCensorshipEvent(isFailure: Boolean) {")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassTypes.kt', 'w') as f:
    f.write(text)
