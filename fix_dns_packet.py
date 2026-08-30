with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DnsPacketEngine.kt', 'r') as f:
    content = f.read()

content = content.replace('''        } catch (e: Exception) {
            android.util.Log.e("DnsPacketEngine", "Error parsing DNS response", e)
        
        return ips''', '''        } catch (e: Exception) {
            android.util.Log.e("DnsPacketEngine", "Error parsing DNS response", e)
        }
        return ips''')

content = content.replace('''        } catch (e: Exception) {
            android.util.Log.e("DnsPacketEngine", "Error parsing detailed DNS response", e)
        
        return records''', '''        } catch (e: Exception) {
            android.util.Log.e("DnsPacketEngine", "Error parsing detailed DNS response", e)
        }
        return records''')

content = content.replace('''                    } catch (e: Exception) {
                        android.util.Log.v("DnsPacketEngine", "HTTPS record param error: ${e.message}")
                    } catch (e: Exception) {
                        android.util.Log.v("DnsPacketEngine", "Critical HTTPS record error")
                    } finally {''', '''                    } catch (e: Exception) {
                        android.util.Log.v("DnsPacketEngine", "HTTPS record param error: ${e.message}")
                    } finally {''')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DnsPacketEngine.kt', 'w') as f:
    f.write(content)
