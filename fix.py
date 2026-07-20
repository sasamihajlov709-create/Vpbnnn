with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()
    
content = content.replace("                    }\n                }\n                c2t.cancel(); t2c.cancel()", "                c2t.cancel(); t2c.cancel()")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
