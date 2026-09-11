with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnState.kt', 'r') as f:
    text = f.read()

text = text.replace('ERROR\n}', 'ERROR,\n    TUN_FALLBACK\n}')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/VpnState.kt', 'w') as f:
    f.write(text)
