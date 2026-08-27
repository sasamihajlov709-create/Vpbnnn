with open("app/src/main/java/com/aistudio/pinkproxy/fresh/NetworkProfileManager.kt", "r") as f:
    text = f.read()

text = text.replace("DpiEngine.clearTimeouts()", "// DpiEngine.clearTimeouts()")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/NetworkProfileManager.kt", "w") as f:
    f.write(text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt", "r") as f:
    text = f.read()

import re
text = re.sub(r'    fun clearTimeouts\(\) \{\n        \}\n    ', '', text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt", "w") as f:
    f.write(text)
