import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    content = f.read()

content = content.replace(
'''            } catch (e: Exception) {
                Log.w("PinkVpnService", "IPv6 not supported on this device, skipping IPv6 routes")
            }
                .setSession("PinkProxy")
                .setMtu(BypassConfig.currentMtu.value)''',
'''            } catch (e: Exception) {
                Log.w("PinkVpnService", "IPv6 not supported on this device, skipping IPv6 routes")
            }
            builder.setSession("PinkProxy")
                   .setMtu(BypassConfig.currentMtu.value)''')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.write(content)
