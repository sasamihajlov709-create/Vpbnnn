with open("app/src/main/java/com/aistudio/pinkproxy/fresh/HappyEyeballsConnector.kt", "r") as f:
    text = f.read()

import re

old_finally = r'''        finally \{
            // Drain and close losing candidate sockets
            launch\(ProxyDispatcher\.io\) \{
                while \(true\) \{
                    val remaining = channel\.tryReceive\(\)\.getOrNull\(\) \?: break
                    if \(remaining != winningSocket\) \{
                        try \{
                            // SO_LINGER 0 forces immediate TCP RST discarding without lingering in TIME_WAIT
                            remaining\.setSoLinger\(true, 0\)
                        \} catch \(ignored: Exception\) \{\}
                        try \{ remaining\.close\(\) \} catch \(ignored: Exception\) \{\}
                    \}
                \}
            \}
        \}'''
new_finally = '''        finally {
            channel.close()
            // Drain and close losing candidate sockets
            while (true) {
                val remaining = channel.tryReceive().getOrNull() ?: break
                if (remaining != winningSocket) {
                    try {
                        // SO_LINGER 0 forces immediate TCP RST discarding without lingering in TIME_WAIT
                        remaining.setSoLinger(true, 0)
                    } catch (ignored: Exception) {}
                    try { remaining.close() } catch (ignored: Exception) {}
                }
            }
        }'''
text = re.sub(old_finally, new_finally, text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/HappyEyeballsConnector.kt", "w") as f:
    f.write(text)
