with open('app/src/main/java/com/aistudio/pinkproxy/fresh/AutoTtlProber.kt', 'r') as f:
    text = f.read()

text = text.replace("kotlinx.coroutines.async {", "async {")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/AutoTtlProber.kt', 'w') as f:
    f.write(text)
print("done")
