import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/AutoTtlProber.kt', 'r') as f:
    code = f.read()

old_code = """                    if (discoveredTtls["global"] == null) {
                        probeDistance(host, 443, vpnService)
                    }
                    if (discoveredMtus["global"] == null) {
                        probeBestMtu(host, 443, vpnService)
                    }"""

new_code = """                    // Always probe periodically to adapt to routing changes
                    val r = ThreadLocalRandom.current().nextInt(100)
                    if (discoveredTtls["global"] == null || r < 20) {
                        probeDistance(host, 443, vpnService)
                    }
                    if (discoveredMtus["global"] == null || r < 10) {
                        probeBestMtu(host, 443, vpnService)
                    }"""

if old_code in code:
    with open('app/src/main/java/com/aistudio/pinkproxy/fresh/AutoTtlProber.kt', 'w') as f:
        f.write(code.replace(old_code, new_code))
else:
    print("Could not find the block to replace")

