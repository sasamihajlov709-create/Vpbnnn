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

    init {
        if (android.os.Build.VERSION.SDK_INT < 28) {
            try {
                fdField = java.net.SocketImpl::class.java.getDeclaredField("fd")
                fdField?.isAccessible = true
                getImplMethod = java.net.Socket::class.java.getDeclaredMethod("getImpl")
                getImplMethod?.isAccessible = true
            } catch (e: Exception) { Log.v("TtlHelper", "Reflection not available") }
        }
    }

    fun setTtl(socket: Socket, ttl: Int): Boolean {
        return try {
            val fd = if (fdField != null && getImplMethod != null) {
                val impl = getImplMethod!!.invoke(socket)
                fdField!!.get(impl) as? java.io.FileDescriptor
            } else {
                null
            }

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
                    try { pfd.close() } catch (e: Exception) { Log.v("TtlHelper", "Ignored: ${e.message}") }
                }
            }
        } catch (e: Exception) {
            Log.v("TtlHelper", "Failed to set TTL: ${e.message}")
            false
        }
    }

    fun setUdpTtl(socket: java.net.DatagramSocket, ttl: Int): Boolean {
        return try {
            val pfd = ParcelFileDescriptor.fromDatagramSocket(socket)
            try {
                val isIpv6 = socket.inetAddress is java.net.Inet6Address
                if (isIpv6) {
                    Os.setsockoptInt(pfd.fileDescriptor, OsConstants.IPPROTO_IPV6, OsConstants.IPV6_UNICAST_HOPS, ttl)
                } else {
                    Os.setsockoptInt(pfd.fileDescriptor, OsConstants.IPPROTO_IP, OsConstants.IP_TTL, ttl)
                }
                true
            } finally {
                try { pfd.close() } catch (e: Exception) { Log.v("TtlHelper", "Ignored: ${e.message}") }
            }
        } catch (e: Exception) {
            Log.v("TtlHelper", "Failed to set UDP TTL: ${e.message}")
            false
        }
    }
}
