import os
import re

directory = 'app/src/main/java/com/aistudio/pinkproxy/fresh/'
for filename in os.listdir(directory):
    if filename.endswith(".kt"):
        path = os.path.join(directory, filename)
        with open(path, 'r') as f:
            content = f.read()
        
        orig = content
        # Fix double replacements
        content = content.replace('if (if (vpnService?.protect(s) == false) throw java.io.IOException("protect failed") == false) throw java.io.IOException("protect failed")', 
                                  'if (vpnService?.protect(s) == false) throw java.io.IOException("protect failed")')
        
        content = content.replace('if (if (vpnService?.protect(socket) == false) throw java.io.IOException("protect failed") == false) throw java.io.IOException("protect failed")',
                                  'if (vpnService?.protect(socket) == false) throw java.io.IOException("protect failed")')
                                  
        content = content.replace('try { if (vpnService?.protect(socket) == false) throw java.io.IOException("protect failed") } catch(e: Exception) { Log.v("DnsOptimizer", "Socket protection failed: ${e.message}") }',
                                  'if (vpnService?.protect(socket) == false) throw java.io.IOException("protect failed")')

        content = content.replace('if (if (VpnSessionManager.currentSession?.vpnService?.protect(sock) == false) throw java.io.IOException("protect failed") == false) throw java.io.IOException("protect failed")',
                                  'if (VpnSessionManager.currentSession?.vpnService?.protect(sock) == false) throw java.io.IOException("protect failed")')
        
        content = content.replace('if (VpnSessionManager.currentSession?.if (vpnService?.protect(sock) == false) throw java.io.IOException("protect failed") == false) throw java.io.IOException("protect failed")',
                                  'if (VpnSessionManager.currentSession?.vpnService?.protect(sock) == false) throw java.io.IOException("protect failed")')

        if content != orig:
            with open(path, 'w') as f:
                f.write(content)
