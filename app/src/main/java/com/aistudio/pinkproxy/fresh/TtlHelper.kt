package com.aistudio.pinkproxy.fresh

import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import java.net.Inet6Address
import java.net.Socket
import java.net.DatagramSocket
import java.io.FileDescriptor

object TtlHelper {

    init {
        try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                org.lsposed.hiddenapibypass.HiddenApiBypass.addHiddenApiExemptions("")
                Log.v("TtlHelper", "Successfully bypassed hidden API restrictions")
            }
        } catch (e: Throwable) {
            Log.e("TtlHelper", "Failed to bypass hidden API restrictions", e)
        }
    }

    private fun withFd(socket: Any, block: (FileDescriptor) -> Unit) {
        var pfd: ParcelFileDescriptor? = null
        try {
            pfd = when (socket) {
                is Socket -> ParcelFileDescriptor.fromSocket(socket)
                is DatagramSocket -> ParcelFileDescriptor.fromDatagramSocket(socket)
                else -> null
            }
            val fd = pfd?.fileDescriptor
            if (fd != null && fd.valid()) {
                block(fd)
            }
        } catch (e: Throwable) {
            Log.v("TtlHelper", "withFd error: ${e.message}")
        } finally {
            try { pfd?.close() } catch (e: Throwable) {}
        }
    }

    private fun setsockoptInt(fd: FileDescriptor, level: Int, option: Int, value: Int) {
        try {
            android.system.Os.setsockoptInt(fd, level, option, value)
        } catch (e: Throwable) {
            Log.v("TtlHelper", "setsockoptInt failed: ${e.message}")
        }
    }

    fun tuneSocket(socket: Socket) {
        try {
            socket.tcpNoDelay = true
            socket.keepAlive = true
            try { socket.sendBufferSize = 128 * 1024 } catch (e: Throwable) {}
            try { socket.receiveBufferSize = 128 * 1024 } catch (e: Throwable) {}
        } catch (e: Throwable) {}
    }

    fun setTtl(socket: Any, ttl: Int) {
        withFd(socket) { fd ->
            val isIpv6 = if (socket is Socket) socket.inetAddress is Inet6Address 
                         else (socket as? DatagramSocket)?.inetAddress is Inet6Address
            if (isIpv6) {
                setsockoptInt(fd, 41, 16, ttl) // IPPROTO_IPV6=41, IPV6_UNICAST_HOPS=16
            } else {
                setsockoptInt(fd, 0, 2, ttl) // IPPROTO_IP=0, IP_TTL=2
            }
        }
    }

    fun setUdpTtl(socket: DatagramSocket, ttl: Int, isIpv6: Boolean = false) {
        withFd(socket) { fd ->
            if (isIpv6) {
                setsockoptInt(fd, 41, 16, ttl)
            } else {
                setsockoptInt(fd, 0, 2, ttl)
            }
        }
    }

    fun setMss(socket: Socket, mss: Int) {
        withFd(socket) { fd ->
            setsockoptInt(fd, 6, 2, mss)
        }
    }

    fun setWindowSize(socket: Any, size: Int) {
        try {
            val safeSize = if (size <= 0) 1 else size
            if (socket is Socket) socket.receiveBufferSize = safeSize
            else if (socket is DatagramSocket) socket.receiveBufferSize = safeSize
        } catch (e: Throwable) {}
    }

    fun setNoFrag(socket: Any, noFrag: Boolean) {
        withFd(socket) { fd ->
            setsockoptInt(fd, 0, 10, if (noFrag) 2 else 0)
        }
    }

    fun getSocketTtl(socket: Socket): Int {
        return 64
    }

    fun setLowTtlTemporary(socket: Socket, lowTtl: Int, delayMs: Long) {
        val originalTtl = getSocketTtl(socket)
        setTtl(socket, lowTtl)
        ProxyDispatcher.mainScope.launch {
            delay(delayMs)
            setTtl(socket, originalTtl)
        }
    }
}
