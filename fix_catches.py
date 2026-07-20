import os
import re

def process_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Replace empty catch blocks: `catch (e: Exception) {}` -> `catch (e: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${e.message}") }`
    content = re.sub(r'catch\s*\(\s*([a-zA-Z0-9_]+)\s*:\s*Exception\s*\)\s*\{\s*\}', r'catch (\1: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${\1.message}") }', content)

    # Replace catch blocks that just have a comment: `catch (e: Exception) { /* comment */ }`
    content = re.sub(r'catch\s*\(\s*([a-zA-Z0-9_]+)\s*:\s*Exception\s*\)\s*\{\s*/\*.*?\*/\s*\}', r'catch (\1: Exception) { android.util.Log.v("PinkProxy", "Ignored: ${\1.message}") }', content)

    with open(filepath, 'w') as f:
        f.write(content)

for root, _, files in os.walk('app/src/main/java/com/aistudio/pinkproxy/fresh/'):
    for f in files:
        if f.endswith('.kt'):
            process_file(os.path.join(root, f))
