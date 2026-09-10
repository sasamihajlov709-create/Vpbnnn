with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    lines = f.readlines()

new_lines = []
skip = False
for i, line in enumerate(lines):
    if 'vpnStartupCoordinator = VpnStartupCoordinator(' in line:
        skip = True
    if skip:
        if '        )' in line:
            skip = False
        continue
        
    new_lines.append(line)
    if 'protectSocket = { socket -> protect(socket) }' in line:
        # It's at the end of healthMonitor init
        # We need to wait for the closing brace and parenthesis.
        pass
    
    if '        )' in line and i > 135 and i < 155 and 'healthMonitor =' in "".join(lines[max(0, i-15):i]):
        new_lines.append('''
        vpnStartupCoordinator = VpnStartupCoordinator(
            vpnService = this,
            vpnTunnelManager = vpnTunnelManager!!,
            transportEngineCoordinator = transportEngineCoordinator,
            recoveryCoordinator = recoveryCoordinator,
            healthMonitor = healthMonitor!!
        )
''')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.writelines(new_lines)
