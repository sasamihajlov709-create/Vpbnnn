import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocolImpls.kt", "r") as f:
    text = f.read()

# Replace the fallback logic so it doesn't double-record
new_text = re.sub(
    r'catch \(e: Exception\) \{\s*if \(e is CancellationException\) throw e\s*Log\.w\("DohDnsProtocols", "Cronet DoH failed, falling back to OkHttp: \$\{e\.message\}"\)\s*com\.aistudio\.pinkproxy\.fresh\.cronet\.CronetMetrics\.recordFallbackToTcp\(\)\s*\}',
    r'''catch (e: Exception) {
                if (e is CancellationException) throw e
                Log.w("DohDnsProtocols", "Cronet DoH failed or parse error, falling back to OkHttp: ${e.message}")
                // If the error was from Cronet itself (network issue), we fallback to OkHttp TCP pipeline.
                // CronetMetrics.recordFallbackToTcp() is already recorded in onResponseStarted if it negotiated HTTP/2.
                // But if it's a total failure, we record fallback here.
                if (e !is java.lang.IllegalArgumentException) { // Assuming parse errors are IllegalArg or similar
                    com.aistudio.pinkproxy.fresh.cronet.CronetMetrics.recordFallbackToTcp()
                }
            }''',
    text, flags=re.DOTALL
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/DnsProtocolImpls.kt", "w") as f:
    f.write(new_text)
