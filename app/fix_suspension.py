import sys
import re

file_path = 'app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt'

with open(file_path, 'r') as f:
    content = f.read()

# Add import
if 'import kotlinx.coroutines.sync.Mutex' in content and 'import kotlinx.coroutines.sync.withLock' not in content:
    content = content.replace('import kotlinx.coroutines.sync.Mutex', 'import kotlinx.coroutines.sync.Mutex\nimport kotlinx.coroutines.sync.withLock')

# Replace withLock with manual lock/unlock because of suspension
# This is tricky with regex. Let's try to find blocks of withLock and replace them.

def replace_with_lock(match):
    indent = match.group(1)
    body = match.group(2)
    # Adjust body indentation
    new_body = "\n".join([line for line in body.split("\n")])
    return f'{indent}writeMutex.lock()\n{indent}try {{\n{body}\n{indent}}} finally {{\n{indent}    writeMutex.unlock()\n{indent}}}'

# Pattern for withLock { ... }
# We need to handle nested braces or just be very specific.
# Since we only have one level of writeMutex now, it's easier.

# Simplest way: replace the start and end separately if we can identify them.
# But regex with groups is better.

# Let's try a simpler replacement for the known patterns
content = content.replace('writeMutex.withLock {', 'writeMutex.lock(); try {')
# This is not enough because we need the 'finally { writeMutex.unlock() }' at the end of the block.

# I'll use a line-by-line approach in Python.
lines = content.split("\n")
new_lines = []
stack = []
for i, line in enumerate(lines):
    if 'writeMutex.withLock {' in line:
        indent = line[:line.find('writeMutex')]
        new_lines.append(f'{indent}writeMutex.lock()')
        new_lines.append(f'{indent}try {{')
        stack.append(indent)
    elif len(stack) > 0 and line.strip() == '}' and line.startswith(stack[-1]):
        # This might be the closing brace of withLock
        # We need to check if it's the right one. 
        # In our case, the indentation should match the 'writeMutex' line.
        indent = stack.pop()
        new_lines.append(f'{indent}}} finally {{')
        new_lines.append(f'{indent}    writeMutex.unlock()')
        new_lines.append(f'{indent}}}')
    else:
        new_lines.append(line)

content = "\n".join(new_lines)

with open(file_path, 'w') as f:
    f.write(content)
