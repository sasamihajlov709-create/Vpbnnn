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
        } catch (e: Exception) { Log.v("TtlHelper", "Reflection limited or unavailable") }
    }

    private fun getFileDescriptor(socket: Any): java.io.FileDescriptor? {
        return try {
            val impl = when (socket) {
                is Socket -> getImplMethod?.invoke(socket)
                is java.net.DatagramSocket -> getDatagramImplMethod?.invoke(socket)
                else -> null
            }
            if (impl != null) fdField?.get(impl) as? java.io.FileDescriptor else null
        } catch (e: Exception) { null }
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
                    try { pfd.close() } catch (e: Exception) {}
                }
            }
        } catch (e: Exception) {
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
                    try { pfd.close() } catch (e: Exception) {}
                }
            }
        } catch (e: Exception) {
            Log.v("TtlHelper", "Failed to set UDP TTL: ${e.message}")
            false
        }
    }
}
