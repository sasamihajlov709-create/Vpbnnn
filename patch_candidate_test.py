import re
with open("app/src/test/java/com/aistudio/pinkproxy/fresh/CandidateHierarchicalPriorTest.kt", "r") as f:
    content = f.read()

content = content.replace("TLS_RECORD_SPLIT", "TLS_RECORD_FRAGMENTATION")
content = content.replace("failureReason = null,", "failureReason = null, quality = ObservationQuality.APPLICATION_DATA_EXCHANGED,")

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/CandidateHierarchicalPriorTest.kt", "w") as f:
    f.write(content)

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/DpiPolicyIsolationTest.kt", "r") as f:
    content = f.read()

content = content.replace("import org.junit.Assert.assertNotEquals", "import org.junit.Assert.assertNotEquals\nimport org.junit.Assert.assertTrue")
content = content.replace(
    "fingerprint = DpiAnalyzer.CensorshipFingerprint(rstRate = 0.9, sniBlockRate = 0.9)",
    "fingerprint = DpiAnalyzer.CensorshipFingerprint(rstRate = 0.9, sniBlockRate = 0.9, udpBlockRate = 0.0, dnsBlockRate = 0.0, timeoutRate = 0.0, stallRate = 0.0, jitter = 0.0, intensity = 0, transport = TransportType.TCP)"
)
content = content.replace(
    "fingerprint = DpiAnalyzer.CensorshipFingerprint(udpBlockRate = 0.0)",
    "fingerprint = DpiAnalyzer.CensorshipFingerprint(rstRate = 0.0, sniBlockRate = 0.0, udpBlockRate = 0.0, dnsBlockRate = 0.0, timeoutRate = 0.0, stallRate = 0.0, jitter = 0.0, intensity = 0, transport = TransportType.UDP)"
)

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/DpiPolicyIsolationTest.kt", "w") as f:
    f.write(content)
