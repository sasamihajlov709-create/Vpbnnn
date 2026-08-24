import re
with open("app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyBehaviorTest.kt", "r") as f:
    content = f.read()

# Replace the extra '}' with just one '}' before the tracking stream class
content = content.replace("    }\n}\n\nclass TrackingByteArrayOutputStream", "    }\n\nclass TrackingByteArrayOutputStream")

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyBehaviorTest.kt", "w") as f:
    f.write(content)
