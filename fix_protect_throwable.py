import os
import re

directory = 'app/src/main/java/com/aistudio/pinkproxy/fresh/'

for filename in os.listdir(directory):
    if filename.endswith(".kt"):
        path = os.path.join(directory, filename)
        with open(path, 'r') as f:
            content = f.read()
            
        original_content = content
        
        # 1. Fix vpnService?.protect ignoring return value (we skip UdpTransportManager as it's already fixed)
        if filename != "UdpTransportManager.kt":
            # Match: vpnService?.protect(socket) -> if (vpnService?.protect(socket) == false) throw java.io.IOException("protect failed")
            content = re.sub(r'try\s*\{\s*vpnService\?\.protect\((.*?)\)\s*\}\s*catch\s*\([^)]*\)\s*\{\s*.*?\}',
                             r'if (vpnService?.protect(\1) == false) throw java.io.IOException("protect failed")', content)
            
            content = re.sub(r'try\s*\{\s*VpnSessionManager\.currentSession\?\.vpnService\?\.protect\((.*?)\)\s*\}\s*catch\s*\([^)]*\)\s*\{\s*\}',
                             r'if (VpnSessionManager.currentSession?.vpnService?.protect(\1) == false) throw java.io.IOException("protect failed")', content)
                             
            content = re.sub(r'vpnService\?\.protect\((.*?)\)', 
                             r'if (vpnService?.protect(\1) == false) throw java.io.IOException("protect failed")', content)

        # 2. Fix catch (Throwable) or catch(e: Throwable) -> catch (e: Exception)
        # Note: sometimes it's `catch (e: Throwable)`
        content = re.sub(r'catch\s*\(\s*([a-zA-Z0-9_]+)\s*:\s*Throwable\s*\)', r'catch (\1: Exception)', content)
        
        # Avoid throwing IOException if already inside a weird block, but our regex just replaces it. 
        # Actually it's better to just replace `vpnService?.protect` since throwing IOException is correct.
        
        if content != original_content:
            with open(path, 'w') as f:
                f.write(content)
