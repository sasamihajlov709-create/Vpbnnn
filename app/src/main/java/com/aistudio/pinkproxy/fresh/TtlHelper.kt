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
                try {
                    org.lsposed.hiddenapibypass.HiddenApiBypass.addHiddenApiExemptions("")
                    Log.v("TtlHelper", "Successfully bypassed hidden API restrictions")
                } catch (t: Throwable) {
                    Log.d("TtlHelper", "HiddenApiBypass not supported in current runtime: ${t.message}")
                }
            }
        } catch (t: Throwable) {
            Log.d("TtlHelper", "Failed to bypass hidden API restrictions: ${t.message}")
        }
    }

    private fun withFd(socket: Any, block: (FileDescriptor) -> Unit) {
        var pfd: ParcelFileDescriptor? = null
        try {
            pfd = when (socket) {
                is Socket -> try { ParcelFileDescriptor.fromSocket(socket) } catch (t: Throwable) { null }
                is DatagramSocket -> try { ParcelFileDescriptor.fromDatagramSocket(socket) } catch (t: Throwable) { null }
                else -> null
            }
            val fd = pfd?.fileDescriptor
            if (fd != null && fd.valid()) {
                block(fd)
            }
        } catch (t: Throwable) {
            // Gracefully ignore in non-Android or unsupported environments
        } finally {
            try { pfd?.close() } catch (t: Throwable) {}
        }
    }

    private fun setsockoptInt(fd: FileDescriptor, level: Int, option: Int, value: Int) {
        try {
            android.system.Os.setsockoptInt(fd, level, option, value)
        } catch (t: Throwable) {
            // Gracefully ignore
        }
    }

    fun tuneSocket(socket: Socket) {
        try {
            socket.tcpNoDelay = true
            socket.keepAlive = true
            
            val networkType = BypassConfig.currentNetworkType.value
            val (sndBuf, rcvBuf) = when (networkType) {
                NetworkType.WIFI -> 256 * 1024 to 512 * 1024
                NetworkType.MOBILE -> 128 * 1024 to 256 * 1024
                else -> 64 * 1024 to 128 * 1024
            }
            
            try { socket.sendBufferSize = sndBuf } catch (e: Exception) {
                Log.v("TtlHelper", "Failed to set send buffer: ${e.message}")
            }
            try { socket.receiveBufferSize = rcvBuf } catch (e: Exception) {
                Log.v("TtlHelper", "Failed to set receive buffer: ${e.message}")
            }
            
            setIpTos(socket, 0x10 or 0x08) // IPTOS_LOWDELAY | IPTOS_THROUGHPUT
            setTcpQuickAck(socket, true)
            
            // Настройка Keep-Alive для мобильных сетей (агрессивное обнаружение разрывов)
            if (networkType == NetworkType.MOBILE) {
                setKeepAliveParams(socket, 20, 5, 3) // 20s idle, 5s interval, 3 probes
            }
        } catch (e: Exception) {}
    }

    fun setIpTos(socket: Any, tos: Int) {
        withFd(socket) { fd ->
            setsockoptInt(fd, 0, 1, tos) // IPPROTO_IP=0, IP_TOS=1
        }
    }

    fun setTcpQuickAck(socket: Socket, enabled: Boolean) {
        withFd(socket) { fd ->
            setsockoptInt(fd, 6, 12, if (enabled) 1 else 0) // IPPROTO_TCP=6, TCP_QUICKACK=12
        }
    }

    fun setKeepAliveParams(socket: Socket, idle: Int, interval: Int, count: Int) {
        withFd(socket) { fd ->
            try {
                setsockoptInt(fd, 6, 4, idle)     // TCP_KEEPIDLE = 4
                setsockoptInt(fd, 6, 5, interval) // TCP_KEEPINTVL = 5
                setsockoptInt(fd, 6, 6, count)    // TCP_KEEPCNT = 6
            } catch (e: Exception) {
                Log.v("TtlHelper", "setKeepAliveParams failed: ${e.message}")
            }
        }
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
            setsockoptInt(fd, 6, 2, mss) // IPPROTO_TCP=6, TCP_MAXSEG=2
        }
    }

    fun applyMssClamping(socket: Socket, host: String?) {
        try {
            val baseMtu = BypassConfig.getMtuForTransport(TransportType.TCP)
            val isIpv6 = socket.inetAddress is Inet6Address || (host != null && host.contains(":"))
            val overhead = if (isIpv6) 60 else 40
            
            // Dynamic host-specific probed Path MTU with cellular network safety floor
            val probedMtu = if (!host.isNullOrBlank()) AutoTtlProber.getDiscoveredMtu(host) else null
            val effectiveMtu = probedMtu ?: baseMtu

            // Clamp MSS between 512 and (effectiveMtu - overhead)
            val clampedMss = (effectiveMtu - overhead).coerceIn(512, 1460)
            setMss(socket, clampedMss)
        } catch (e: Exception) {}
    }

    fun setWindowSize(socket: Any, size: Int) {
        try {
            val safeSize = if (size <= 0) 1 else size
            if (socket is Socket) socket.receiveBufferSize = safeSize
            else if (socket is DatagramSocket) socket.receiveBufferSize = safeSize
        } catch (e: Exception) {}
    }

    fun setNoFrag(socket: Any, noFrag: Boolean) {
        withFd(socket) { fd ->
            setsockoptInt(fd, 0, 10, if (noFrag) 2 else 0)
        }
    }

    private fun getsockoptInt(fd: FileDescriptor, level: Int, option: Int): Int {
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
            } catch (e2: Exception) {
                BypassConfig.currentTtl
            }
        } catch (e: Exception) {
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
    }

    fun setLowTtlTemporary(socket: Socket, lowTtl: Int, delayMs: Long) {
        val originalTtl = getSocketTtl(socket)
        setTtl(socket, lowTtl)
        ProxyDispatcher.globalScope.launch {
            delay(delayMs)
            setTtl(socket, originalTtl)
        }
    }
}
