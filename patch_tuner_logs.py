with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt", "r") as f:
    content = f.read()

content = content.replace(
    'Log.i("ProactiveAutoTuner", "Discovered viable candidate strategy $candidate for $host proactively!")',
    'Log.i("ProactiveAutoTuner", "Discovered candidate strategy $candidate for $host proactively! (Phase: ${ObservationQuality.TLS_RECORD_RECEIVED.label})")'
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTuner.kt", "w") as f:
    f.write(content)
