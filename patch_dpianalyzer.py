import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt", "r") as f:
    text = f.read()

replacement = """        val rttKey = "${currentProfileId}|$transport"
        val transportHistory = DpiEngine.rttHistory[rttKey]?.let { synchronized(it) { it.toList() } } ?: emptyList()"""

text = re.sub(r'        val transportHistory = DpiEngine\.rttHistory\[transport\]\?\.let \{ synchronized\(it\) \{ it\.toList\(\) \} \} \?: emptyList\(\)', replacement, text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DpiAnalyzer.kt", "w") as f:
    f.write(text)
