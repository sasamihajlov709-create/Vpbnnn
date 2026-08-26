with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt", "r") as f:
    content = f.read()

# Fix the broken interpolation
content = content.replace(
    'Thread(r, "PinkProxy-IO-${threadId.getAndIncrement()    fun cancelAllBackgroundJobs() {\n        mainScope.coroutineContext[kotlinx.coroutines.Job]?.cancelChildren()\n    }\n}").apply',
    'Thread(r, "PinkProxy-IO-${threadId.getAndIncrement()}").apply'
)

if "fun cancelAllBackgroundJobs()" not in content:
    # Safely add to the end of the file
    content = content.replace(
        'val mainScope = CoroutineScope(io + SupervisorJob() + globalHandler)\n}',
        'val mainScope = CoroutineScope(io + SupervisorJob() + globalHandler)\n\n    fun cancelAllBackgroundJobs() {\n        mainScope.coroutineContext[kotlinx.coroutines.Job]?.cancelChildren()\n    }\n}'
    )

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt", "w") as f:
    f.write(content)

print("Fixed ProxyDispatcher")
