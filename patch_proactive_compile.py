import re
with open("app/src/test/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTunerLockTest.kt", "r") as f:
    content = f.read()

content = content.replace(
    "timestamp = System.currentTimeMillis()",
    "timestamp = System.currentTimeMillis(), quality = ObservationQuality.APPLICATION_DATA_EXCHANGED"
)

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTunerLockTest.kt", "w") as f:
    f.write(content)
