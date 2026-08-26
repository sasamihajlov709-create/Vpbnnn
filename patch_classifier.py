with open("app/src/main/java/com/aistudio/pinkproxy/fresh/HostClassifier.kt", "r") as f:
    content = f.read()

content = content.replace("fun classify(host: String): HostCategory {", "fun classify(host: String?): HostCategory {\n        if (host == null) return HostCategory.OTHER")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/HostClassifier.kt", "w") as f:
    f.write(content)
