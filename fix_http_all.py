with open("app/src/main/java/com/aistudio/pinkproxy/fresh/HttpStrategyHandler.kt", "r") as f:
    text = f.read()

import re

# Remove the broken `return }` block
text = re.sub(r'        if \(strategy == BypassStrategy\.HTTP_METHOD_CASE_MANGLE\) \{\s+val fuzzed = FakePacketHelper\.mangleHttpMethodCase\(data, length\)\s+output\.write\(fuzzed, 0, fuzzed\.size\)\s+output\.flush\(\)\s+return\s+\}\s+return\s+\}', 
r'''        if (strategy == BypassStrategy.HTTP_METHOD_CASE_MANGLE) {
            val fuzzed = FakePacketHelper.mangleHttpMethodCase(data, length)
            output.write(fuzzed, 0, fuzzed.size)
            output.flush()
            return
        }''', text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/HttpStrategyHandler.kt", "w") as f:
    f.write(text)
