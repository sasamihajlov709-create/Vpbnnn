import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ui/ProfileBackupCard.kt", "r") as f:
    content = f.read()

content = content.replace("BypassConfig.loadSettings(context)", "BypassConfig.loadTuningSettings(context)")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ui/ProfileBackupCard.kt", "w") as f:
    f.write(content)
