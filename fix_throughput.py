import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "r") as f:
    code = f.read()

# Replace ProxyStats.bytesTransferred.value with totalWrittenClient.get() inside the throughputJob
code = code.replace("var lastTotalForStall = ProxyStats.bytesTransferred.value", "var lastTotalForStall = totalWrittenClient.get()")
code = code.replace("val total = ProxyStats.bytesTransferred.value", "val total = totalWrittenClient.get()")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "w") as f:
    f.write(code)
