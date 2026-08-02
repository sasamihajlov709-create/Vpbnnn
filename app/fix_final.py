import sys

file_path = 'app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt'

with open(file_path, 'r') as f:
    content = f.read()

# Fix the half-baked replacement
content = content.replace('writeMutex.lock(); try {', 'writeMutex.lock()\n                                        try {')

# Actually, let's just do a clean replacement of the whole block pattern
# I'll use a more robust line-by-line processor

lines = content.split('\n')
new_lines = []
for line in lines:
    if 'writeMutex.lock()' in line and 'try {' not in line:
        indent = line[:line.find('writeMutex')]
        new_lines.append(line)
        new_lines.append(f'{indent}try {{')
    elif 'writeMutex.lock(); try {' in line:
        indent = line[:line.find('writeMutex')]
        new_lines.append(f'{indent}writeMutex.lock()')
        new_lines.append(f'{indent}try {{')
    elif line.strip() == '} finally {':
         new_lines.append(line)
    elif 'writeMutex.unlock()' in line:
         new_lines.append(line)
    else:
        new_lines.append(line)

with open(file_path, 'w') as f:
    f.write('\n'.join(new_lines))
