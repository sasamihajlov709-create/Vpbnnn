with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpAssociationTable.kt', 'r') as f:
    text = f.read()

text = text.replace('val bytesReceived = AtomicLong(0L) {', 'val bytesReceived = AtomicLong(0L)\n')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/UdpAssociationTable.kt', 'w') as f:
    f.write(text)
