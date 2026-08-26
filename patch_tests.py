import re
with open("app/src/test/java/com/aistudio/pinkproxy/fresh/DpiPolicyIsolationTest.kt", "r") as f:
    content = f.read()

content = content.replace("assertTrue(tcpIntensity > 80)", "assertTrue(\"tcpIntensity was $tcpIntensity\", tcpIntensity > 80)")
content = content.replace("assertEquals(0, udpIntensity)", "assertEquals(\"udpIntensity was $udpIntensity\", 0, udpIntensity)")

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/DpiPolicyIsolationTest.kt", "w") as f:
    f.write(content)

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTunerLockTest.kt", "r") as f:
    content = f.read()

content = content.replace("assertTrue(\"Memory should NOT be null for strong observation\", memory != null)", "assertTrue(\"Memory should NOT be null for strong observation, memory was $memory\", memory != null)")

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTunerLockTest.kt", "w") as f:
    f.write(content)
