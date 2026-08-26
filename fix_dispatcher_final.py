with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt", "r") as f:
    lines = f.readlines()

new_lines = []
skip = False
for line in lines:
    if "Thread(r, \"PinkProxy-IO-${threadId.getAndIncrement()" in line:
        new_lines.append('            Thread(r, "PinkProxy-IO-${threadId.getAndIncrement()}").apply {\n')
        skip = True
    elif skip and "}\").apply {" in line:
        skip = False
    elif not skip:
        new_lines.append(line)

content = "".join(new_lines)
if "fun cancelAllBackgroundJobs()" not in content:
    content = content.replace(
        "val mainScope = CoroutineScope(io + SupervisorJob() + globalHandler)\n}",
        "val mainScope = CoroutineScope(io + SupervisorJob() + globalHandler)\n\n    fun cancelAllBackgroundJobs() {\n        mainScope.coroutineContext[kotlinx.coroutines.Job]?.cancelChildren()\n    }\n}"
    )

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt", "w") as f:
    f.write(content)
