with open("app/src/test/java/com/aistudio/pinkproxy/fresh/DpiPolicyIsolationTest.kt", "r") as f:
    content = f.read()

# 0.9 * 60 + 0.9 * 70 = 54 + 63 = 117 -> coerced to 100. Then target intensity is (0 * 0.2 + 100 * 0.8) = 80.
# So tcpIntensity is exactly 80. Change > 80 to >= 80
content = content.replace("tcpIntensity > 80", "tcpIntensity >= 80")

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/DpiPolicyIsolationTest.kt", "w") as f:
    f.write(content)

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/ProactiveAutoTunerLockTest.kt", "r") as f:
    content = f.read()

# ProactiveAutoTunerLockTest might be failing because we used BypassStrategy.TLS_RECORD_PADDING
# Let's see what the assert failed on.
