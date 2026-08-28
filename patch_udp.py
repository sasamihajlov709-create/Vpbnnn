import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt", "r") as f:
    text = f.read()

replacement = """                                val sessionKey = UdpAssociationTable.findClientForKey(endpointKey)
                                
                                if (sessionKey == null) {
                                    continue // Strict UDP session routing. Drop packet if destination is unknown.
                                }
                                val targetAddr = sessionKey.clientAddress
                                val targetPort = sessionKey.clientPort"""

text = re.sub(r'                                val sessionKey = UdpAssociationTable\.findClientForKey\(endpointKey\)\s+val \(targetAddr, targetPort\) = if \(sessionKey != null\) \{\s+Pair\(sessionKey\.clientAddress, sessionKey\.clientPort\)\s+\} else \{\s+// Fallback to latest registered client endpoint\s+clientEndpoints\.values\.firstOrNull\(\) \?: continue\s+\}', replacement, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt", "w") as f:
    f.write(text)
