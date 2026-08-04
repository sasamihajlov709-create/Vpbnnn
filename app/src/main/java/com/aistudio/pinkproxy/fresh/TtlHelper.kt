package com.aistudio.pinkproxy.fresh

import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import java.net.Inet6Address
import java.net.Socket
import java.net.DatagramSocket
import java.io.FileDescriptor

@android.annotation.SuppressLint("SoonBlockedPrivateApi")
object TtlHelper {
    private var setsockoptIntMethod: java.lang.reflect.Method? = null
    private var getsockoptIntMethod: java.lang.reflect.Method? = null
    private var setsockoptByteMethod: java.lang.reflect.Method? = null
    
    // Fallback reflection for FD if PFD fails (older versions)
    private var fdField: java.lang.reflect.Field? = null

    init {
        try {
            val osClass = Class.forName("android.system.Os")
            setsockoptIntMethod = osClass.getDeclaredMethod("setsockoptInt", FileDescriptor::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            getsockoptIntMethod = osClass.getDeclaredMethod("getsockoptInt", FileDescriptor::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            
            try {
                setsockoptByteMethod = osClass.getDeclaredMethod("setsockoptBytes", FileDescriptor::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, ByteArray::class.java)
            } catch (e: Throwable) {}
            
            // Still try to get FD field from FileDescriptor class if needed, or from SocketImpl
            try {
                fdField = FileDescriptor::class.java.getDeclaredField("descriptor")
                fdField?.isAccessible = true
            } catch (e: Throwable) {
                try {
                    fdField = java.net.SocketImpl::class.java.getDeclaredField("fd")
                    fdField?.isAccessible = true
                } catch (e2: Throwable) {}
            }
        } catch (e: Throwable) {
            Log.d("TtlHelper", "Core reflection failed: ${e.message}")
        }
    }

    private fun withFd(socket: Any, block: (FileDescriptor) -> Unit) {
        try {
            // Priority: ParcelFileDescriptor (Public API, safe)
            val pfd = when (socket) {
                is Socket -> ParcelFileDescriptor.fromSocket(socket)
                is DatagramSocket -> ParcelFileDescriptor.fromDatagramSocket(socket)
                else -> null
            }
            
            try {
                val fd = pfd?.fileDescriptor
                if (fd != null && fd.valid()) {
                    block(fd)
                }
            } finally {
                try { pfd?.close() } catch (e: Throwable) {}
            }
        } catch (e: Throwable) {
            Log.v("TtlHelper", "withFd error: ${e.message}")
        }
    }

    private fun setsockoptInt(fd: FileDescriptor, level: Int, option: Int, value: Int) {
        try {
            setsockoptIntMethod?.invoke(null, fd, level, option, value)
        } catch (e: Throwable) {}
    }

    private fun getsockoptInt(fd: FileDescriptor, level: Int, option: Int): Int {
        return try {
            getsockoptIntMethod?.invoke(null, fd, level, option) as? Int ?: 64
        } catch (e: Throwable) { 64 }
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
        var result = 64
        withFd(socket) { fd ->
            val isIpv6 = socket.inetAddress is Inet6Address
            result = if (isIpv6) {
                getsockoptInt(fd, 41, 16)
            } else {
                getsockoptInt(fd, 0, 2)
            }
        }
        return result
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
