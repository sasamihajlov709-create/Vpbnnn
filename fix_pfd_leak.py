with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt", "r") as f:
    text = f.read()

import re

old_tun = r'''            dupFd = vpnInterface\.dup\(\)
            rawFd = dupFd\.detachFd\(\)
            key\.setDevice\("fd://\$rawFd"\)
            key\.setLogLevel\("error"\)
            engine\.Engine\.insert\(key\)'''
new_tun = '''            dupFd = vpnInterface.dup()
            rawFd = dupFd.detachFd()
            try { vpnInterface.close() } catch (ignored: Exception) {} // Close original to prevent FD leak
            key.setDevice("fd://$rawFd")
            key.setLogLevel("error")
            engine.Engine.insert(key)'''

text = re.sub(old_tun, new_tun, text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt", "w") as f:
    f.write(text)
