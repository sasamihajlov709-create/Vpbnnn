with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt", "r") as f:
    text = f.read()

# Replace DiscardOldestPolicy with CallerRunsPolicy to avoid hanging coroutines
text = text.replace("ThreadPoolExecutor.DiscardOldestPolicy()", "ThreadPoolExecutor.CallerRunsPolicy()")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProxyDispatcher.kt", "w") as f:
    f.write(text)
