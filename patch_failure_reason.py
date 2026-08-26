with open("app/src/main/java/com/aistudio/pinkproxy/fresh/FailureReason.kt", "r") as f:
    content = f.read()

new_reasons = """    TIMEOUT,
    TCP_RESET,
    SSL_HANDSHAKE_ERROR,
    CONNECTION_REFUSED,
    CENSORSHIP_STALL,
    DNS_POISONED,
    MTU_EXCEEDED,
    PROTOCOL_ERROR,
    HANDSHAKE_TIMEOUT,
    NETWORK_LOST,
    TARGET_UNAVAILABLE,
    LOCAL_SOCKET_ERROR,
    UNKNOWN"""

import re
content = re.sub(r'    TIMEOUT,.*?UNKNOWN', new_reasons, content, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/FailureReason.kt", "w") as f:
    f.write(content)
