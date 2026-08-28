with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "r") as f:
    text = f.read()

text = text.replace("targetPort == 443", "port == 443")
text = text.replace("targetPort == 80", "port == 80")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "w") as f:
    f.write(text)
