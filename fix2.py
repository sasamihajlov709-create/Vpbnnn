import re
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """                //
                    //
                    //
                    //
                        //
                        //
                    //
                        //
                    }"""

repl = """                """

if find in content:
    content = content.replace(find, repl)
    print("Fixed!")
else:
    print("Not found.")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
