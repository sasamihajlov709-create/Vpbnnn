with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'r') as f:
    text = f.read()
    
# Remove the first closing brace after startVpn block and add one to end of file if missing
text = text.replace('    }\n\n}\n    private fun extractIpsFromDnsUrl', '    }\n\n    private fun extractIpsFromDnsUrl')
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnStartupCoordinator.kt', 'w') as f:
    f.write(text)
