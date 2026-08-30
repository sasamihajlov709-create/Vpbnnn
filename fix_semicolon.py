import os

directory = 'app/src/main/java/com/aistudio/pinkproxy/fresh/'
for filename in os.listdir(directory):
    if filename.endswith(".kt"):
        path = os.path.join(directory, filename)
        with open(path, 'r') as f:
            content = f.read()
            
        orig = content
        
        content = content.replace('val s = Socket()\n        if (vpnService?.protect(s)', 'val s = Socket();\n        if (vpnService?.protect(s)')
        
        if content != orig:
            with open(path, 'w') as f:
                f.write(content)
