import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RobustResolver.kt', 'r') as f:
    content = f.read()

# Fix 1: The bad emptyList() try { channel.send(res) } catch ...
content = re.sub(
    r'emptyList\(\)\s+try \{ channel\.send\(res\) \}\"\)\s+\} catch \(e: Exception\) \{',
    r'emptyList()\n                }\n                try { channel.send(res) } catch (e: Exception) {',
    content
)

# Fix 2: The other bad emptyList() ... if (res.isNotEmpty()) {
content = re.sub(
    r'emptyList\(\)\s+if \(res\.isNotEmpty\(\)\) \{',
    r'emptyList()\n                }\n                if (res.isNotEmpty()) {',
    content
)

# Fix 3: Duplicate catch blocks on channel.send(res) inside the first launch
content = re.sub(
    r'try \{ channel\.send\(res\) \} catch \(e: CancellationException\) \{\s*throw e\s*\} catch \(e: Exception\) \{\s*Log.v\([^)]+\)\s*\} catch \(e: Exception\) \{\s*Log.v\([^)]+\)\s*\}',
    r'try { channel.send(res) } catch (e: CancellationException) {\n                            throw e\n                        } catch (e: Exception) {\n                            Log.v("RobustResolver", "Failed to send result to channel: ${e.message}")\n                        }',
    content
)

# Wait, the first one is: emptyList() \n try { channel.send(res) } catch (e: CancellationException) ...
content = re.sub(
    r'emptyList\(\)\s+try \{ channel\.send\(res\) \} catch',
    r'emptyList()\n                        }\n                        try { channel.send(res) } catch',
    content
)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RobustResolver.kt', 'w') as f:
    f.write(content)
