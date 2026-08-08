package com.aistudio.pinkproxy.fresh

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.content.Context
import android.util.Log
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext

object NetworkProber {

    suspend fun checkBaselineInternet(context: Context?): Boolean {
        var internetUp = false
        
        // System check
        val cm = context?.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val activeNetwork = cm?.activeNetwork
        val capabilities = cm?.getNetworkCapabilities(activeNetwork)
        val systemInternet = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true &&
                             capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        
        if (systemInternet) return true

        // Manual probe
        val baselineDomains = listOf(
            "https://ya.ru", 
            "https://www.google.com/generate_204", 
            "https://www.apple.com/library/test/success.html"
        )
        
        for (domain in baselineDomains) {
            var conn: HttpURLConnection? = null
            try {
                conn = URL(domain).openConnection(Proxy.NO_PROXY) as HttpURLConnection
                if (conn is HttpsURLConnection) {
                    val sslContext = SSLContext.getInstance("TLS")
                    sslContext.init(null, null, null)
                    PinkVpnService.instance?.let { vpn ->
                        conn.sslSocketFactory = ProtectedSSLSocketFactory(sslContext.socketFactory, vpn)
                    }
                }
                conn.connectTimeout = 3000
                conn.readTimeout = 3000
                conn.requestMethod = "GET"
                if (conn.responseCode in 200..399) {
                    internetUp = true
                    break
                }
            } catch (e: Throwable) {
                Log.v("NetworkProber", "Baseline probe failed for $domain: ${e.message}")
            } finally {
                try { conn?.disconnect() } catch (e: Throwable) {}
            }
        }
        return internetUp
    }

    suspend fun checkProxyReachable(proxyPort: Int): Boolean {
        return try {
            val sock = java.net.Socket()
            try { PinkVpnService.instance?.protect(sock) } catch (e: Throwable) {}
            sock.connect(InetSocketAddress("127.0.0.1", proxyPort), 1000)
            sock.close()
            true
        } catch (e: Throwable) {
            false
        }
    }

    suspend fun probeServiceViaProxy(
        name: String, 
        url: String, 
        proxyPort: Int
    ): ServiceChecker.ServiceStatus {
        val start = System.currentTimeMillis()
        var isUp = false
        var attempt = 0
        var successfulLatency = 0L
        
        while (attempt < 2 && !isUp) {
            attempt++
            var connection: HttpURLConnection? = null
            val attemptStart = System.currentTimeMillis()
            try {
                val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", proxyPort))
                connection = URL(url).openConnection(proxy) as HttpURLConnection
                connection.connectTimeout = 5000
                connection.readTimeout = 5000
                connection.instanceFollowRedirects = true
                connection.requestMethod = "HEAD"
                connection.setRequestProperty("User-Agent", "Mozilla/5.0 (PinkProxy/1.0)")
                
                var code = connection.responseCode
                if (code == 405) { 
                    connection.disconnect()
                    connection = URL(url).openConnection(proxy) as HttpURLConnection
                    connection.connectTimeout = 5000
                    connection.readTimeout = 5000
                    connection.requestMethod = "GET"
                    code = connection.responseCode
                }
                isUp = (code in 200..399)
                
                val duration = System.currentTimeMillis() - attemptStart
                if (isUp) {
                    successfulLatency = duration
                    val threshold = if (name.contains("Stream")) 4500 else 7000
                    if ((name.contains("YouTube") || name.contains("Telegram")) && duration > threshold) {
                        isUp = false 
                    }
                }
            } catch (e: Throwable) {
                isUp = false
            } finally {
                try { connection?.disconnect() } catch (e: Throwable) {}
            }
            if (!isUp && attempt < 2) kotlinx.coroutines.delay(1000)
        }
        
        val finalLatency = if (isUp && successfulLatency > 0) successfulLatency else (System.currentTimeMillis() - start)
        return ServiceChecker.ServiceStatus(name, url, isUp, if (isUp) finalLatency else 0)
    }
}
