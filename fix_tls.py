import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TlsStrategyHandler.kt", "r") as f:
    text = f.read()

bad_groups = [
    r'BypassStrategy\.TLS_REHANDSHAKE_FAKE -> \{.*?\n\s+\}',
    r'BypassStrategy\.TLS_HELLO_JUNK, BypassStrategy\.TLS_LEGACY_HELLOS -> \{.*?\n\s+\}',
    r'BypassStrategy\.TLS_MULTI_SNI -> \{.*?\n\s+\}',
    r'BypassStrategy\.TLS_CHROME_HELLO_FAKE, BypassStrategy\.TLS_FIREFOX_HELLO_FAKE, BypassStrategy\.TLS_13_HELLO_FAKE -> \{.*?\n\s+\}'
]

for pattern in bad_groups:
    header = pattern.split(' ->')[0].replace('\\.', '.')
    replacement = header + """ -> {
                // Warning: Corrupting TLS payloads or faking cryptographic handshakes breaks application-level TLS context.
                // Reverting to transparent forward.
                output.write(data, 0, length)
                output.flush()
            }"""
    text = re.sub(pattern, replacement, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TlsStrategyHandler.kt", "w") as f:
    f.write(text)
