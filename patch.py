with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpStrategyHandler.kt", "r") as f:
    lines = f.readlines()

# we want to delete 175 and 176 which are "                }\n" and "            }\n"
# and insert the two lines that I deleted.
lines[174] = ""
lines[175] = ""
lines.insert(176, "            BypassStrategy.UDP_PADDING_CHAOS -> {\n")
lines.insert(177, "                val mtu = 1400\n")

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpStrategyHandler.kt", "w") as f:
    f.writelines(lines)
