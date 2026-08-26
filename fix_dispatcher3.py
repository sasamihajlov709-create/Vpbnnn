with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt", "r") as f:
    content = f.read()

bad_string = """Thread(r, "PinkProxy-IO-${threadId.getAndIncrement()    fun cancelAllBackgroundJobs() {
        mainScope.coroutineContext[kotlinx.coroutines.Job]?.cancelChildren()
    }
}").apply {"""

good_string = """Thread(r, "PinkProxy-IO-${threadId.getAndIncrement()}").apply {"""

content = content.replace(bad_string, good_string)

# Add the method to the very end of the file safely
if "fun cancelAllBackgroundJobs()" not in content:
    content = content.replace("val mainScope = CoroutineScope(io + SupervisorJob() + globalHandler)\n}", "val mainScope = CoroutineScope(io + SupervisorJob() + globalHandler)\n\n    fun cancelAllBackgroundJobs() {\n        mainScope.coroutineContext[kotlinx.coroutines.Job]?.cancelChildren()\n    }\n}")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt", "w") as f:
    f.write(content)
