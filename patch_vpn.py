with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt", "r") as f:
    code = f.read()

code = code.replace("stopForeground(true)", """if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }""")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt", "w") as f:
    f.write(code)
