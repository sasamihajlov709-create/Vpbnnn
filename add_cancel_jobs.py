import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt", "r") as f:
    content = f.read()

cancel_method = """
    fun cancelAllBackgroundJobs() {
        mainScope.coroutineContext[kotlinx.coroutines.Job]?.cancelChildren()
    }
}"""

if "cancelAllBackgroundJobs" not in content:
    content = content.replace("}", cancel_method, 1)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt", "w") as f:
    f.write(content)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt", "r") as f:
    content = f.read()

if "ProxyDispatcher.cancelAllBackgroundJobs()" not in content:
    content = content.replace("engineScope.cancel()", "engineScope.cancel()\n        ProxyDispatcher.cancelAllBackgroundJobs()")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt", "w") as f:
    f.write(content)

print("Updated ProxyDispatcher and PinkVpnService")
