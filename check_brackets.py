with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsCacheManager.kt", "r") as f:
    text = f.read()

opens = text.count('{')
closes = text.count('}')
print(f"opens: {opens}, closes: {closes}")
