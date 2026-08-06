package com.aistudio.pinkproxy.fresh

import java.util.concurrent.ConcurrentHashMap

object HostClassifier {
    private val cache = ConcurrentHashMap<String, HostCategory>(256)
    
    fun classify(host: String): HostCategory {
        if (host.isEmpty()) return HostCategory.OTHER
        if (cache.size > 1000) cache.clear()
        
        return cache.getOrPut(host) {
            val h = host.lowercase()
            when {
                h.contains("youtube") || h.contains("netflix") || h.contains("twitch") || h.contains("googlevideo") || h.contains("vimeo") || h.contains("ytimg") || h.contains("ggpht") || h.contains("rutube") || h.contains("vkvideo") || h.contains("movies") || h.contains("stream") -> HostCategory.STREAMING
                h.contains("facebook") || h.contains("instagram") || h.contains("twitter") || h.contains("tiktok") || h.contains("linkedin") || h.contains("reddit") || h.contains("fbcdn") || h.contains("twimg") || h.contains("x.com") || h.contains("vk.com") || h.contains("ok.ru") || h.contains("snapchat") || h.contains("pinterest") -> HostCategory.SOCIAL
                h.contains("whatsapp") || h.contains("telegram") || h.contains("discord") || h.contains("signal.org") || h.contains("slack") || h.contains("viber") || h.contains("skype") || h.contains("t.me") || h.contains("tdesktop") || h.contains("messenger") || h.contains("zoom.us") -> HostCategory.MESSENGER
                h.contains("google") || h.contains("bing") || h.contains("duckduckgo") || h.contains("yahoo") || h.contains("baidu") || h.contains("yandex") || h.contains("ask.com") || h.contains("ecosia") || h.contains("wolframalpha") -> HostCategory.SEARCH
                h.contains("openai") || h.contains("anthropic") || h.contains("mistral") || h.contains("perplexity") || h.contains("gemini") || h.contains("chatgpt") || h.contains("claude") || h.contains("deepseek") || h.contains("cohere") || h.contains("grok") || h.contains("llama") || h.contains("huggingface") -> HostCategory.AI
                h.contains("bank") || h.contains("crypto") || h.contains("binance") || h.contains("paypal") || h.contains("visa") || h.contains("stripe") || h.contains("wallet") || h.contains("coinbase") || h.contains("revolut") || h.contains("tinkoff") || h.contains("sber") || h.contains("p2p") || h.contains("blockchain") || h.contains("metamask") || h.contains("ledger") -> HostCategory.FINANCE
                h.contains("github") || h.contains("gitlab") || h.contains("npm") || h.contains("docker") || h.contains("stackoverflow") || h.contains("jetbrains") || h.contains("android") || h.contains("maven") || h.contains("gradle") || h.contains("kotlin") || h.contains("bitbucket") || h.contains("visualstudio") || h.contains("azure") || h.contains("aws") || h.contains("digitalocean") || h.contains("heroku") -> HostCategory.DEV
                h.contains("cloudflare") || h.contains("akamai") || h.contains("fastly") || h.contains("cloudfront") || h.contains("bunny") || h.contains("gvt1") || h.contains("edge") || h.contains("cdn") || h.contains("unpkg") || h.contains("jsdelivr") -> HostCategory.CDN
                h.contains("steam") || h.contains("epicgames") || h.contains("roblox") || h.contains("playstation") || h.contains("xbox") || h.contains("nintendo") || h.contains("blizzard") || h.contains("ea.com") || h.contains("ubisoft") || h.contains("riotgames") || h.contains("unity") -> HostCategory.GAMING
                h.contains("amazon") || h.contains("ebay") || h.contains("aliexpress") || h.contains("shopify") || h.contains("ozon") || h.contains("wildberries") || h.contains("avito") || h.contains("etsy") || h.contains("walmart") -> HostCategory.SHOPPING
                h.contains("ads.") || h.contains("doubleclick") || h.contains("adservice") || h.contains("analytics") || h.contains("telemetry") || h.contains("metrics") || h.contains("crashlytics") || h.contains("segment") || h.contains("mixpanel") -> HostCategory.AD
                h.contains("bbc") || h.contains("cnn") || h.contains("reuters") || h.contains("bloomberg") || h.contains("nytimes") || h.contains("dw.com") || h.contains("rferl") || h.contains("aljazeera") || h.contains("guardian") || h.contains("forbes") -> HostCategory.NEWS
                h.contains("gov") || h.contains("mil") || h.contains("gosuslugi") || h.contains("fsb") || h.contains("mvd") || h.contains("police") -> HostCategory.GOVERNMENT
                h.contains("vpn") || h.contains("proxy") || h.contains("torproject") || h.contains("i2p") || h.contains("shadowsocks") || h.contains("v2ray") || h.contains("wireguard") || h.contains("openvpn") -> HostCategory.SECURITY
                else -> HostCategory.OTHER
            }
        }
    }
}
