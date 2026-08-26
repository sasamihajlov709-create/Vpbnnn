with open("app/src/test/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTunerLockTest.kt", "r") as f:
    content = f.read()

# To get confidence > 0.75 we need more success samples and minimal failures.
# 5 is enough for a mean but stdDev is wide if samples are few. Let's do 20 samples.
content = content.replace("for (i in 1..5) {", "for (i in 1..20) {")

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTunerLockTest.kt", "w") as f:
    f.write(content)
