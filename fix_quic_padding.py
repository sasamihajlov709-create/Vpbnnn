import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

# Replace padding for QUIC
code = code.replace(
    "val padding = FakePacketHelper.buildUdpNoise(rnd.nextInt(256, 512))",
    "val padding = ByteArray(rnd.nextInt(256, 512)) { 0x00 }"
)
code = code.replace(
    "val padding = FakePacketHelper.buildUdpNoise(rnd.nextInt(800, 1100))",
    "val padding = ByteArray(rnd.nextInt(800, 1100)) { 0x00 }"
)
code = code.replace(
    "val padding = FakePacketHelper.buildUdpNoise(rnd.nextInt(64, 128))",
    "val padding = ByteArray(rnd.nextInt(64, 128)) { 0x00 }"
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(code)
