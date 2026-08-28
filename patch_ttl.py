import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TtlHelper.kt", "r") as f:
    text = f.read()

replacement_get = """    private fun getsockoptInt(fd: FileDescriptor, level: Int, option: Int): Int {
        return try {
            val structOsClass = Class.forName("android.system.Os")
            val method = structOsClass.getMethod("getsockoptInt", FileDescriptor::class.java, Int::class.java, Int::class.java)
            method.invoke(null, fd, level, option) as Int
        } catch (e: NoSuchMethodException) {
            // getsockoptInt is hidden in some API levels, fallback to libcore
            try {
                val libcoreClass = Class.forName("libcore.io.Libcore")
                val osField = libcoreClass.getField("os")
                val osObj = osField.get(null)
                val method = osObj.javaClass.getMethod("getsockoptInt", FileDescriptor::class.java, Int::class.java, Int::class.java)
                method.invoke(osObj, fd, level, option) as Int
            } catch (e2: Throwable) {
                BypassConfig.currentTtl
            }
        } catch (e: Throwable) {
            Log.v("TtlHelper", "getsockoptInt failed: ${e.message}")
            BypassConfig.currentTtl
        }
    }

    fun getSocketTtl(socket: Socket): Int {
        var ttl = BypassConfig.currentTtl
        withFd(socket) { fd ->
            ttl = getsockoptInt(fd, 0, 2) // IPPROTO_IP=0, IP_TTL=2
        }
        return ttl
    }"""

text = re.sub(r'    private fun getsockoptInt\(fd: FileDescriptor, level: Int, option: Int\): Int \{.*?    fun getSocketTtl\(socket: Socket\): Int \{.*?    \}', replacement_get, text, flags=re.DOTALL)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TtlHelper.kt", "w") as f:
    f.write(text)
