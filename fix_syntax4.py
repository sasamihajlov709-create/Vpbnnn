with open('app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt', 'r') as f:
    text = f.read()
import sys

# The error says "Syntax error: Unexpected tokens (use ';' to separate expressions on the same line)."
# This usually happens if there are two BypassStrategy items side by side like:
# BypassStrategy.TCP_TIMESTAMP_MANGLE -> { BypassStrategy.TCP_TIMESTAMP_MANGLE -> {
# Wait, I saw this exact thing in tail! 
