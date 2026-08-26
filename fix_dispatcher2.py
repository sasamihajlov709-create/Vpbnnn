with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt", "r") as f:
    content = f.read()

if "import kotlinx.coroutines.cancelChildren" not in content:
    content = content.replace("import kotlinx.coroutines.asCoroutineDispatcher", "import kotlinx.coroutines.asCoroutineDispatcher\nimport kotlinx.coroutines.cancelChildren")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt", "w") as f:
    f.write(content)
