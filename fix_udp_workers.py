import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt", "r") as f:
    code = f.read()

# 1. Replace single channel with array of channels
code = code.replace(
    "val udpOutChannel = kotlinx.coroutines.channels.Channel<Pair<DatagramPacket, String>>(500)",
    "val udpOutChannels = Array(8) { kotlinx.coroutines.channels.Channel<Pair<DatagramPacket, String>>(500) }"
)

# 2. Modify the worker to read from its specific channel
worker_read = """for (work in udpOutChannel) {"""
worker_read_new = """for (work in udpOutChannels[i]) {"""
code = code.replace(worker_read, worker_read_new)

# 3. Fix the trySend part 1
try_send_1 = """udpOutChannel.trySend(DatagramPacket(payload, payload.size, cached.first(), targetPortNum) to targetHost)"""
try_send_1_new = """val hash = (targetHost.hashCode() xor targetPortNum)
                                    val workerIdx = Math.abs(hash) % 8
                                    udpOutChannels[workerIdx].trySend(DatagramPacket(payload, payload.size, cached.first(), targetPortNum) to targetHost)"""
code = code.replace(try_send_1, try_send_1_new)

# 4. Fix the trySend part 2
try_send_2 = """udpOutChannel.trySend(DatagramPacket(payload, payload.size, res.first(), targetPortNum) to targetHost)"""
try_send_2_new = """val hash2 = (targetHost.hashCode() xor targetPortNum)
                                                val workerIdx2 = Math.abs(hash2) % 8
                                                udpOutChannels[workerIdx2].trySend(DatagramPacket(payload, payload.size, res.first(), targetPortNum) to targetHost)"""
code = code.replace(try_send_2, try_send_2_new)

# 5. Fix the close
close_chan = """udpOutChannel.close()"""
close_chan_new = """udpOutChannels.forEach { it.close() }"""
code = code.replace(close_chan, close_chan_new)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/UdpTransportHandler.kt", "w") as f:
    f.write(code)
