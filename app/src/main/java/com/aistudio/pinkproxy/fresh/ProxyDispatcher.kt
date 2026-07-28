package com.aistudio.pinkproxy.fresh

import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.Executors

object ProxyDispatcher {
    val io = Executors.newCachedThreadPool { r ->
        Thread(r, "PinkProxyWorker").apply { isDaemon = true }
    }.asCoroutineDispatcher()
}
