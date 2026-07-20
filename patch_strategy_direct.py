import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find = """    fun getBestStrategyForHost(host: String): BypassStrategy {
        val lHost = host.lowercase(java.util.Locale.ROOT)
        
        // Chaos Mode: If censorship is extreme, randomize every connection to bypass temporal signatures"""

repl = """    fun getBestStrategyForHost(host: String): BypassStrategy {
        val lHost = host.lowercase(java.util.Locale.ROOT)
        
        // Auto-Direct (Split Tunneling): Bypass proxy engine completely for RU domains and known local services
        if (lHost.endsWith(".ru") || lHost.endsWith(".su") || lHost.endsWith(".рф") || 
            lHost.contains("yandex") || lHost.contains("vk.com") || lHost.contains("gosuslugi") ||
            lHost.contains("sberbank") || lHost.contains("tinkoff") || lHost.contains("alfabank") ||
            lHost.contains("mail.ru") || lHost.contains("ozon.ru") || lHost.contains("wildberries") ||
            lHost == "localhost" || lHost.startsWith("192.168.") || lHost.startsWith("10.") || lHost.startsWith("127.")) {
            return BypassStrategy.DIRECT
        }
        
        // Chaos Mode: If censorship is extreme, randomize every connection to bypass temporal signatures"""

if find in content:
    content = content.replace(find, repl)
else:
    print("Could not find block")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
