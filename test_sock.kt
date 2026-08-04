import java.net.Socket
fun main() {
    val s = Socket()
    try {
        s.receiveBufferSize = 0
        println("OK")
    } catch(e: Exception) {
        println("ERROR: " + e.message)
    }
}
