import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/HttpStrategyHandler.kt", "r") as f:
    text = f.read()

# Neutralize dangerous HTTP strategies
text = text.replace('BypassStrategy.HTTP_HOST_REVERSE -> str.replace("Host: $host", "Host: " + host.reversed())', 
                    'BypassStrategy.HTTP_HOST_REVERSE -> str')
text = text.replace('BypassStrategy.HTTP_LINE_SPLIT -> str.replace("\\r\\n", "\\r\\n ")', 
                    'BypassStrategy.HTTP_LINE_SPLIT -> str')

# Also fix the methods that inject fake data like WS_HANDSHAKE_FAKE, HTTP2_PREAMBLE_FAKE, HTTP_METHOD_FAKE
# They are handled in big if-blocks above line 180.
bad_groups = [
    r'if \(strategy == BypassStrategy\.HTTP_METHOD_FAKE\) \{.*?\n\s+\}',
    r'if \(strategy == BypassStrategy\.HTTP2_PREAMBLE_FAKE\) \{.*?\n\s+\}',
    r'if \(strategy == BypassStrategy\.WS_HANDSHAKE_FAKE\) \{.*?\n\s+\}',
    r'if \(strategy == BypassStrategy\.HTTP_CHUNKED_FAKE\) \{.*?\n\s+\}',
    r'if \(strategy == BypassStrategy\.HTTP_PIPELINE_FAKE\) \{.*?\n\s+\}'
]

for pattern in bad_groups:
    text = re.sub(pattern, "", text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/HttpStrategyHandler.kt", "w") as f:
    f.write(text)
