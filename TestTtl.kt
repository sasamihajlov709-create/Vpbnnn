import android.system.Os
import android.system.OsConstants
import java.net.Socket
import android.os.ParcelFileDescriptor

fun setTtl(socket: Socket, ttl: Int) {
    try {
        val pfd = ParcelFileDescriptor.fromSocket(socket)
        val fd = pfd.fileDescriptor
        Os.setsockoptInt(fd, OsConstants.IPPROTO_IP, OsConstants.IP_TTL, ttl)
        pfd.close()
    } catch(e: Exception) {
        e.printStackTrace()
    }
}
