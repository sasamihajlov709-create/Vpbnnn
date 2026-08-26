with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt", "r") as f:
    content = f.read()

old_log = 'Log.i("ProactiveAutoTuner", "Discovered optimal strategy $candidate for $host proactively!")'
new_log = 'Log.i("ProactiveAutoTuner", "Discovered viable candidate strategy $candidate for $host proactively!")'

content = content.replace(old_log, new_log)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt", "w") as f:
    f.write(content)
