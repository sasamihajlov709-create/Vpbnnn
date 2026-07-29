package com.aistudio.pinkproxy.fresh

import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import java.net.Inet6Address
import java.net.Socket
import android.util.Log

@android.annotation.SuppressLint("SoonBlockedPrivateApi")
object TtlHelper {
    private var fdField: java.lang.reflect.Field? = null
    private var getImplMethod: java.lang.reflect.Method? = null
    private var getDatagramImplMethod: java.lang.reflect.Method? = null

    init {
        try {
            fdField = java.net.SocketImpl::class.java.getDeclaredField("fd")
            fdField?.isAccessible = true
            getImplMethod = java.net.Socket::class.java.getDeclaredMethod("getImpl")
            getImplMethod?.isAccessible = true
            getDatagramImplMethod = java.net.DatagramSocket::class.java.getDeclaredMethod("getImpl")
            getDatagramImplMethod?.isAccessible = true
        } catch (e: Throwable) { Log.v("TtlHelper", "Reflection limited or unavailable") }
    }

    private fun getFileDescriptor(socket: Any): java.io.FileDescriptor? {
        return try {
            val impl = when (socket) {
                is Socket -> getImplMethod?.invoke(socket)
                is java.net.DatagramSocket -> getDatagramImplMethod?.invoke(socket)
                else -> null
            }
            if (impl != null) fdField?.get(impl) as? java.io.FileDescriptor else null
        } catch (e: Throwable) { null }
    }

    fun setTtl(socket: Socket, ttl: Int): Boolean {
        return try {
            val fd = getFileDescriptor(socket)
            if (fd != null && fd.valid()) {
                val isIpv6 = socket.inetAddress is java.net.Inet6Address
                if (isIpv6) {
                    Os.setsockoptInt(fd, OsConstants.IPPROTO_IPV6, OsConstants.IPV6_UNICAST_HOPS, ttl)
                } else {
                    Os.setsockoptInt(fd, OsConstants.IPPROTO_IP, OsConstants.IP_TTL, ttl)
                }
                true
            } else {
                // Fallback to ParcelFileDescriptor (dup) if reflection fails
                val pfd = ParcelFileDescriptor.fromSocket(socket)
                try {
                    val isIpv6 = socket.inetAddress is java.net.Inet6Address
                    if (isIpv6) {
                        Os.setsockoptInt(pfd.fileDescriptor, OsConstants.IPPROTO_IPV6, OsConstants.IPV6_UNICAST_HOPS, ttl)
                    } else {
                        Os.setsockoptInt(pfd.fileDescriptor, OsConstants.IPPROTO_IP, OsConstants.IP_TTL, ttl)
                    }
                    true
                } finally {
                    try { pfd.close() } catch (e: Throwable) {}
                }
            }
        } catch (e: Throwable) {
            Log.v("TtlHelper", "Failed to set TTL: ${e.message}")
            false
        }
    }

    fun setUdpTtl(socket: java.net.DatagramSocket, ttl: Int, isIpv6: Boolean = false): Boolean {
        return try {
            val fd = getFileDescriptor(socket)
            if (fd != null && fd.valid()) {
                if (isIpv6 || socket.inetAddress is java.net.Inet6Address) {
                    Os.setsockoptInt(fd, OsConstants.IPPROTO_IPV6, OsConstants.IPV6_UNICAST_HOPS, ttl)
                } else {
                    Os.setsockoptInt(fd, OsConstants.IPPROTO_IP, OsConstants.IP_TTL, ttl)
                }
                true
            } else {
                val pfd = ParcelFileDescriptor.fromDatagramSocket(socket)
                try {
                    if (isIpv6 || socket.inetAddress is java.net.Inet6Address) {
                        Os.setsockoptInt(pfd.fileDescriptor, OsConstants.IPPROTO_IPV6, OsConstants.IPV6_UNICAST_HOPS, ttl)
                    } else {
                        Os.setsockoptInt(pfd.fileDescriptor, OsConstants.IPPROTO_IP, OsConstants.IP_TTL, ttl)
                    }
                    true
                } finally {
                    try { pfd.close() } catch (e: Throwable) {}
                }
            }
        } catch (e: Throwable) {
            Log.v("TtlHelper", "Failed to set UDP TTL: ${e.message}")
            false
        }
    }

    fun setNoFrag(socket: java.net.DatagramSocket, noFrag: Boolean): Boolean {
        return try {
            val fd = getFileDescriptor(socket) ?: return false
            val level = if (socket.inetAddress is java.net.Inet6Address) OsConstants.IPPROTO_IPV6 else OsConstants.IPPROTO_IP
            val optname = if (socket.inetAddress is java.net.Inet6Address) 23 else 10 // IP_MTU_DISCOVER / IPV6_MTU_DISCOVER
            val value = if (noFrag) 2 else 0 // IP_PMTUDISC_DO vs IP_PMTUDISC_DONT
            Os.setsockoptInt(fd, level, optname, value)
            true
        } catch (e: Throwable) { false }
    }

    fun tuneSocket(socket: Socket) {
        try {
            val fd = getFileDescriptor(socket) ?: return
            if (!fd.valid()) return
            
            socket.tcpNoDelay = true
            
            // Set TCP_USER_TIMEOUT (20s) - Option 18 in IPPROTO_TCP (6)
            try { Os.setsockoptInt(fd, 6, 18, 20000) } catch (e: Throwable) {}
            
            // Set TCP_NOTSENT_LOWAT (16KB) - Option 25 in IPPROTO_TCP (6)
            try { Os.setsockoptInt(fd, 6, 25, 16384) } catch (e: Throwable) {}
            
            socket.keepAlive = true
            try {
                Os.setsockoptInt(fd, 6, 4, 60) // TCP_KEEPIDLE
                Os.setsockoptInt(fd, 6, 5, 20) // TCP_KEEPINTVL
                Os.setsockoptInt(fd, 6, 6, 3)  // TCP_KEEPCNT
            } catch (e: Throwable) {}
        } catch (e: Throwable) {
            Log.v("TtlHelper", "Socket tuning failed: ${e.message}")
        }
    }
}
