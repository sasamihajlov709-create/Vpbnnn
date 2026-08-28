with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "r") as f:
    text = f.read()

import re

old_catch = r'''            \} catch \(e: Exception\) \{
                val reason = if \(e\.message\?\.'''
new_catch = '''            } catch (e: Exception) {
                if (e is CancellationException) {
                    try { rs.close() } catch (ex: Exception) {}
                    throw e
                }
                val reason = if (e.message?.'''

text = re.sub(old_catch, new_catch, text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "w") as f:
    f.write(text)
