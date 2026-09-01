import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ObservationQuality.kt", "r") as f:
    content = f.read()

content = content.replace("CONNECT_ONLY(0.0,", "CONNECT_ONLY(0.3,")
content = content.replace("TLS_RECORD_RECEIVED(0.1,", "TLS_RECORD_RECEIVED(0.4,")
content = content.replace("SERVER_HELLO_RECEIVED(0.5,", "SERVER_HELLO_RECEIVED(0.5,")
content = content.replace("HANDSHAKE_COMPLETE(1.0,", "HANDSHAKE_COMPLETE(0.6,")
content = content.replace("APPLICATION_DATA_EXCHANGED(2.0,", "APPLICATION_DATA_EXCHANGED(1.0,")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/ObservationQuality.kt", "w") as f:
    f.write(content)

