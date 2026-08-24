with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "r") as f:
    lines = f.readlines()

missing_code = """                            if (intensity > 70 && java.util.concurrent.ThreadLocalRandom.current().nextInt(100) < 5) {
                                TcpTransportManager.oscillateWindowSize(clientSocket)
                            }
                            clientOut.write(buffer, 0, read)
                            clientOut.flush()
                            ProxyStats.recordStats(sessionId, 0, read.toLong())
                        }
                    } catch (e: java.net.SocketException) {
                        android.util.Log.v("TcpTransport", "Remote to client pump socket closed: ${e.message}")
                    } catch (e: java.io.IOException) {
                        android.util.Log.v("TcpTransport", "Remote to client pump IOException: ${e.message}")
                    } catch (e: Exception) {
                        android.util.Log.v("TcpTransport", "Remote to client pump error: ${e.message}")
                    } finally {
                        if (isStreaming) BufferPool.release(buffer) else BufferPoolManager.release16k(buffer)
                        try { clientSocket.close() } catch (e: Exception) {}
                        try { finalRemoteSocket.close() } catch (e: Exception) {}
                    }
                }

"""
lines.insert(265, missing_code)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/TcpTransportHandler.kt", "w") as f:
    f.writelines(lines)
