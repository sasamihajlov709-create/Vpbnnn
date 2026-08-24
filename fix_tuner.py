import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt", "r") as f:
    content = f.read()

content = content.replace("val diverseExtreme", "val profileId = NetworkProfileManager.currentProfile.value.id\n        val diverseExtreme")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt", "w") as f:
    f.write(content)

