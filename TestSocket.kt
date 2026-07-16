import android.net.LocalSocket
import java.net.Socket
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants

fun test() {
    val s = Socket()
    val pfd = ParcelFileDescriptor.fromSocket(s)
    val fd = pfd.fileDescriptor
    Os.setsockoptInt(fd, OsConstants.IPPROTO_IP, OsConstants.IP_TTL, 3)
}
