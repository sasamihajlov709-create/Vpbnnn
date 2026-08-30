import os

directory = 'app/src/main/java/com/aistudio/pinkproxy/fresh/'
for filename in os.listdir(directory):
    if filename.endswith(".kt"):
        path = os.path.join(directory, filename)
        with open(path, 'r') as f:
            content = f.read()
            
        orig = content
        
        # fix DnsOptimizer.kt:78
        content = content.replace('throw java.io.IOException("protect failed")") }', 'throw java.io.IOException("protect failed")')
        
        # In NetworkProber.kt:75
        content = content.replace('val sock = java.net.Socket()\n            if (VpnSessionManager.currentSession?.vpnService?.protect(sock) == false)', 'val sock = java.net.Socket();\n            if (VpnSessionManager.currentSession?.vpnService?.protect(sock) == false)')

        if content != orig:
            with open(path, 'w') as f:
                f.write(content)
