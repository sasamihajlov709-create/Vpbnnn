import sys

file_path = '/app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt'

with open(file_path, 'r') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    # Fix the missing Mutex and hardcoded TTL in confusion pulse
    if 'TtlHelper.setTtl(socket, 64)' in line:
        line = line.replace('TtlHelper.setTtl(socket, 64)', 'TtlHelper.setTtl(socket, originalTtl)')
    
    # Fix the missing Mutex in TcpTransportHandler loop
    if 'BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, forceConfig, realSni)' in line:
        indent = line[:line.find('BypassConfig')]
        line = f'{indent}writeMutex.withLock {{\n{indent}    BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, forceConfig, realSni)\n{indent}}}\n'
    
    if 'BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, realConfig, realSni)' in line:
        indent = line[:line.find('BypassConfig')]
        line = f'{indent}writeMutex.withLock {{\n{indent}    BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, realConfig, realSni)\n{indent}}}\n'
    
    if 'BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, config, activeHost)' in line:
        indent = line[:line.find('BypassConfig')]
        line = f'{indent}writeMutex.withLock {{\n{indent}    BypassConfig.applyBypass(remoteSocket!!, remoteOut, buffer, n, config, activeHost)\n{indent}}}\n'

    # Fix the fragmented writes
    if 'remoteOut.write(buffer, offset, sz)' in line and 'writeMutex' not in line:
         indent = line[:line.find('remoteOut')]
         line = f'{indent}writeMutex.withLock {{\n{indent}    remoteOut.write(buffer, offset, sz)\n{indent}    remoteOut.flush()\n{indent}    oscillateWindowSize(remoteSocket!!, currentIntensity)\n{indent}}}\n'
    
    # Skip the original flush and oscillate lines that we just added inside the mutex
    if 'remoteOut.flush()' in line and 'writeMutex' not in line and len(new_lines) > 0 and 'writeMutex.withLock' in new_lines[-1]:
         continue
    if 'oscillateWindowSize(remoteSocket!!, currentIntensity)' in line and 'writeMutex' not in line and len(new_lines) > 0 and 'writeMutex.withLock' in new_lines[-1]:
         continue

    new_lines.append(line)

with open(file_path, 'w') as f:
    f.writelines(new_lines)
