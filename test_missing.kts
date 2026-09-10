import java.io.File

val registryStr = File("app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyExecutionRegistry.kt").readText()
val strategyStr = File("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassStrategy.kt").readText()

val mapped = Regex("BypassStrategy\\.([A-Z0-9_]+)").findAll(registryStr).map { it.groupValues[1] }.toSet()
val declared = Regex("([A-Z0-9_]+)\\(").findAll(strategyStr).map { it.groupValues[1] }.toSet()

val missing = declared - mapped
println("Missing: $missing")
