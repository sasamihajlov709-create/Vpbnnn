with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt", "r") as f:
    text = f.read()

import re

old_block = r'''                                if \(sessionKey != null\) \{
                                    UdpAssociationTable\.touchSession\(sessionKey, receivedBytes = inPacket\.length\.toLong\(\)\)
                                \}'''
new_block = '''                                UdpAssociationTable.touchSession(sessionKey, receivedBytes = inPacket.length.toLong())'''

text = re.sub(old_block, new_block, text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt", "w") as f:
    f.write(text)
