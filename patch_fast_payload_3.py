import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'r') as f:
    content = f.read()

find3 = """                        if (isRecv && r > 2048) BypassConfig.TrafficShaper.pace(BypassConfig.isPanicMode, r)
                    }
                }
            } catch (e: Exception) {"""

repl3 = """                        if (isRecv && r > 2048) BypassConfig.TrafficShaper.pace(BypassConfig.isPanicMode, r)
                    }
                    totalProcessedBytes += r
                }
            } catch (e: Exception) {"""

if find3 in content:
    content = content.replace(find3, repl3)
else:
    print("Failed to find totalProcessedBytes increment")

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyServer.kt', 'w') as f:
    f.write(content)
