with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ObservationQuality.kt", "r") as f:
    content = f.read()

# Change HANDSHAKE_COMPLETE minLevelForHostMemory to false
old_handshake = "HANDSHAKE_COMPLETE(1.0, true)"
new_handshake = "HANDSHAKE_COMPLETE(1.0, false)"
content = content.replace(old_handshake, new_handshake)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ObservationQuality.kt", "w") as f:
    f.write(content)
