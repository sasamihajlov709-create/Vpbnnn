with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    text = f.read()

print("tun2socks command:", [line.strip() for line in text.split('\n') if "key.setProxy" in line or "key.setDevice" in line])
