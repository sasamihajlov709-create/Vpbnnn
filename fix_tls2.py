import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TlsStrategyHandler.kt", "r") as f:
    text = f.read()

# Fix the broken body for TLS_CHROME_HELLO_FAKE
# It currently has the replaced part and then trailing garbage:
#             BypassStrategy.TLS_CHROME_HELLO_FAKE, BypassStrategy.TLS_FIREFOX_HELLO_FAKE, BypassStrategy.TLS_13_HELLO_FAKE -> {
#                 // Warning: Corrupting TLS payloads or faking cryptographic handshakes breaks application-level TLS context.
#                 // Reverting to transparent forward.
#                 output.write(data, 0, length)
#                 output.flush()
#             }
#                 TtlHelper.setTtl(socket, StrategyUtils.getFakeTtl(host, rnd))
#                 output.write(fakeHello)
#                 output.flush()
#                 delay(rnd.nextLong(2, 6))
#                 TtlHelper.setTtl(socket, BypassConfig.currentTtl)
#                 output.write(data, 0, length)
#                 output.flush()
#             }

text = re.sub(
r'            BypassStrategy\.TLS_CHROME_HELLO_FAKE, BypassStrategy\.TLS_FIREFOX_HELLO_FAKE, BypassStrategy\.TLS_13_HELLO_FAKE -> \{.*?\n\s+output\.flush\(\)\n\s+\}\n.*?output\.flush\(\)\n\s+\}',
"""            BypassStrategy.TLS_CHROME_HELLO_FAKE, BypassStrategy.TLS_FIREFOX_HELLO_FAKE, BypassStrategy.TLS_13_HELLO_FAKE -> {
                // Warning: Corrupting TLS payloads or faking cryptographic handshakes breaks application-level TLS context.
                // Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
            }""", text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TlsStrategyHandler.kt", "w") as f:
    f.write(text)
