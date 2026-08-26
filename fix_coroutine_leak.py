import re

# Add engineScope.cancel() to PinkVpnService.onDestroy()
with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt", "r") as f:
    content = f.read()

content = content.replace(
    "override fun onDestroy() {\n        super.onDestroy()\n        val appContext = applicationContext",
    "override fun onDestroy() {\n        super.onDestroy()\n        val appContext = applicationContext\n        engineScope.cancel()"
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt", "w") as f:
    f.write(content)

print("Updated PinkVpnService.kt")
