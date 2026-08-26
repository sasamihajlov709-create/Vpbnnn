with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    content = f.read()

content = content.replace(
    "fun getBestStrategyForHost(host: String, transport: TransportType): BypassStrategy",
    "fun getBestStrategyForHost(host: String?, transport: TransportType): BypassStrategy"
)
content = content.replace(
    "fun isHostProbablyCensored(host: String): Boolean",
    "fun isHostProbablyCensored(host: String?): Boolean"
)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(content)
