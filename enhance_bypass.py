import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    code = f.read()

# For BypassConfig, we want to add OOB data right after fake packet output.write(...) if it's not already there
# But wait, we can just replace output.write({fake}); output.flush() with:
# output.write({fake}); output.flush(); try { socket.sendUrgentData(256) } catch(e: Throwable) {}

# Let's check where TtlHelper.setTtl(socket, 64) is called, and insert OOB before it.
pattern = r"(output\.write\(\s*(?:fake|ghost|keep)\s*\)\s*;\s*output\.flush\(\)\s*)"
replacement = r"\1try { socket.sendUrgentData(java.util.concurrent.ThreadLocalRandom.current().nextInt(256)) } catch(e: Throwable) {}; "
code = re.sub(pattern, replacement, code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(code)
