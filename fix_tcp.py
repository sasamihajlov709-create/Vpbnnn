import re

def fix_file(filename):
    with open(filename, "r") as f:
        text = f.read()

    # We want to replace `if (readBytes > 0) {`
    # with a strict check. But we need targetPort or just port.
    
    # In TcpTransportHandler.kt:
    replacement = r'''                val isTls = BypassApplier.isProbableTls(responseBuf, readBytes)
                val isHttp = BypassApplier.isProbableHttp(responseBuf, readBytes)
                val isSuccess = if (targetPort == 443) {
                    isTls && readBytes > 16
                } else if (targetPort == 80) {
                    isHttp && readBytes > 10
                } else {
                    readBytes > 0
                }

                if (isSuccess) {'''
    text = re.sub(r'                if \(readBytes > 0\) \{', replacement, text)

    with open(filename, "w") as f:
        f.write(text)

fix_file("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt")

def fix_race(filename):
    with open(filename, "r") as f:
        text = f.read()

    replacement = r'''            val isTls = BypassApplier.isProbableTls(responseBuf, readBytes)
            val isHttp = BypassApplier.isProbableHttp(responseBuf, readBytes)
            val isSuccess = if (port == 443) {
                isTls && readBytes > 16
            } else if (port == 80) {
                isHttp && readBytes > 10
            } else {
                readBytes > 0
            }

            if (isSuccess) {'''
    text = re.sub(r'            if \(readBytes > 0\) \{', replacement, text)

    with open(filename, "w") as f:
        f.write(text)

fix_race("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpRaceConnector.kt")
