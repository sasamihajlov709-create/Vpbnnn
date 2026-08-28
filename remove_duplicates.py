with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsCacheManager.kt", "r") as f:
    text = f.read()

import re

# Remove the ones I added which are right before `fun putDetailed`
# In `fix_missing_methods.py`, I did:
# text = re.sub(r'    fun putDetailed\(', missing_methods + '\n    fun putDetailed(', text)

# Let's just find that block and remove ensureEfficiency and clearAll from it.

added_methods = r'''    private fun ensureEfficiency\(\) \{
        if \(dnsCache\.size > MAX_DNS_CACHE_SIZE\) \{
            clearExpired\(\)
            if \(dnsCache\.size > MAX_DNS_CACHE_SIZE\) \{
                dnsCache\.clear\(\)
            \}
        \}
    \}

    fun clearAll\(\) \{
        dnsCache\.clear\(\)
        detailedDnsCache\.clear\(\)
        negativeCache\.clear\(\)
    \}'''

text = re.sub(added_methods, '', text)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsCacheManager.kt", "w") as f:
    f.write(text)
