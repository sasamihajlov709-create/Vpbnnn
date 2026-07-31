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
    private var fdField: java.lang.reflect.Field? = null
    private var getImplMethod: java.lang.reflect.Method? = null
    private var getDatagramImplMethod: java.lang.reflect.Method? = null
    
    private var setsockoptIntMethod: java.lang.reflect.Method? = null
    private var getsockoptIntMethod: java.lang.reflect.Method? = null
    private var setsockoptByteMethod: java.lang.reflect.Method? = null

    init {
        try {
            fdField = java.net.SocketImpl::class.java.getDeclaredField("fd")
            fdField?.isAccessible = true
            getImplMethod = java.net.Socket::class.java.getDeclaredMethod("getImpl")
            getImplMethod?.isAccessible = true
            getDatagramImplMethod = DatagramSocket::class.java.getDeclaredMethod("getImpl")
            getDatagramImplMethod?.isAccessible = true
            
            val osClass = Class.forName("android.system.Os")
            setsockoptIntMethod = osClass.getDeclaredMethod("setsockoptInt", FileDescriptor::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            getsockoptIntMethod = osClass.getDeclaredMethod("getsockoptInt", FileDescriptor::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            
            try {
                setsockoptByteMethod = osClass.getDeclaredMethod("setsockoptBytes", FileDescriptor::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, ByteArray::class.java)
            } catch (e: Throwable) {
                // Some versions might have different name or not have it
            }
        } catch (e: Throwable) {
            Log.e("TtlHelper", "Reflection failed", e)
        }
    }

    private fun getFileDescriptor(socket: Any): FileDescriptor? {
        return try {
            val impl = when (socket) {
                is Socket -> getImplMethod?.invoke(socket)
                is DatagramSocket -> getDatagramImplMethod?.invoke(socket)
                else -> null
            }
            if (impl != null) {
                fdField?.get(impl) as? FileDescriptor
            } else null
        } catch (e: Throwable) {
            null
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
        try {
            val fd = getFileDescriptor(socket)
            if (fd != null && fd.valid()) {
                val isIpv6 = if (socket is Socket) socket.inetAddress is Inet6Address else (socket as? DatagramSocket)?.inetAddress is Inet6Address
                // IPPROTO_IP = 0, IP_TTL = 4, IPPROTO_IPV6 = 41, IPV6_UNICAST_HOPS = 16
                if (isIpv6) {
                    setsockoptInt(fd, 41, 16, ttl)
                } else {
                    setsockoptInt(fd, 0, 4, ttl)
                }
            }
        } catch (e: Throwable) {}
    }

    fun setUdpTtl(socket: DatagramSocket, ttl: Int, isIpv6: Boolean = false) {
        try {
            val fd = getFileDescriptor(socket)
            if (fd != null && fd.valid()) {
                if (isIpv6) {
                    setsockoptInt(fd, 41, 16, ttl)
                } else {
                    setsockoptInt(fd, 0, 4, ttl)
                }
            }
        } catch (e: Throwable) {}
    }

    fun setMss(socket: Socket, mss: Int) {
        try {
            val fd = getFileDescriptor(socket)
            if (fd != null && fd.valid()) {
                // IPPROTO_TCP = 6, TCP_MAXSEG = 2
                setsockoptInt(fd, 6, 2, mss)
            }
        } catch (e: Throwable) {}
    }

    fun setWindowSize(socket: Any, size: Int) {
        try {
            if (socket is Socket) socket.receiveBufferSize = size
            else if (socket is DatagramSocket) socket.receiveBufferSize = size
        } catch (e: Throwable) {}
    }

    fun setNoFrag(socket: Any, noFrag: Boolean) {
        try {
            val fd = getFileDescriptor(socket)
            if (fd != null && fd.valid()) {
                // IPPROTO_IP = 0, IP_MTU_DISCOVER = 10, IP_PMTUDISC_DO = 2, IP_PMTUDISC_DONT = 0
                setsockoptInt(fd, 0, 10, if (noFrag) 2 else 0)
            }
        } catch (e: Throwable) {}
    }

    fun getSocketTtl(socket: Socket): Int {
        return try {
            val fd = getFileDescriptor(socket)
            if (fd != null && fd.valid()) {
                val isIpv6 = socket.inetAddress is Inet6Address
                if (isIpv6) {
                    getsockoptInt(fd, 41, 16)
                } else {
                    getsockoptInt(fd, 0, 4)
                }
            } else 64
        } catch (e: Throwable) { 64 }
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
