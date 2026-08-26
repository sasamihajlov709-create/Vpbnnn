with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ObservationQuality.kt", "r") as f:
    content = f.read()

content = content.replace(
    "enum class ObservationQuality(val weight: Double, val minLevelForHostMemory: Boolean) {",
    "enum class ObservationQuality(val weight: Double, val minLevelForHostMemory: Boolean, val label: String) {"
)
content = content.replace("CONNECT_ONLY(0.0, false),", 'CONNECT_ONLY(0.0, false, "Probing"),')
content = content.replace("TLS_RECORD_RECEIVED(0.1, false),", 'TLS_RECORD_RECEIVED(0.1, false, "Viable"),')
content = content.replace("SERVER_HELLO_RECEIVED(0.5, false),", 'SERVER_HELLO_RECEIVED(0.5, false, "Promising"),')
content = content.replace("HANDSHAKE_COMPLETE(1.0, false),", 'HANDSHAKE_COMPLETE(1.0, false, "Likely Good"),')
content = content.replace("APPLICATION_DATA_EXCHANGED(2.0, true),", 'APPLICATION_DATA_EXCHANGED(2.0, true, "Optimal"),')
content = content.replace("SUSTAINED_DATA_TRANSFER(3.0, true);", 'SUSTAINED_DATA_TRANSFER(3.0, true, "Verified");')

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ObservationQuality.kt", "w") as f:
    f.write(content)
