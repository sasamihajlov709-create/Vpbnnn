import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RobustResolver.kt', 'r') as f:
    content = f.read()

content = content.replace('''                val res = try { fallbackDns() } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    emptyList()                                try { channel.send(res) }")                } catch (e: Exception) {
                    Log.v("RobustResolver", "Critical error sending fallback result to channel: ${e.message}")
                }
            }
        }
        
        var result = emptyList<InetAddress>()
        val receivedResults = mutableListOf<List<InetAddress>>()
        var completed = 0
        
        try {
            while (completed < queries.size) {
                val res = try { withTimeout(5000L) { channel.receive() } } catch (e: CancellationException) {
                    if (e !is TimeoutCancellationException) throw e
                    emptyList()
                } catch (e: Exception) {
                    emptyList()                                if (res.isNotEmpty()) {''', '''                val res = try { fallbackDns() } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    emptyList()
                }
                try { channel.send(res) } catch (e: Exception) {
                    Log.v("RobustResolver", "Critical error sending fallback result to channel: ${e.message}")
                }
            }
        }
        
        var result = emptyList<InetAddress>()
        val receivedResults = mutableListOf<List<InetAddress>>()
        var completed = 0
        
        try {
            while (completed < queries.size) {
                val res = try { withTimeout(5000L) { channel.receive() } } catch (e: CancellationException) {
                    if (e !is TimeoutCancellationException) throw e
                    emptyList()
                } catch (e: Exception) {
                    emptyList()
                }
                if (res.isNotEmpty()) {''')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/RobustResolver.kt', 'w') as f:
    f.write(content)
