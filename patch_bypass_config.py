with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "r") as f:
    content = f.read()

old_set_mtu = """    fun setMtu(mtu: Int) {
        val new = mtu.coerceIn(576, 1500)
        if (_currentMtu.value != new) {
            _currentMtu.value = new
            DpiPolicyEngine.transportPolicies[TransportType.TCP]?.mtu = new
            DpiPolicyEngine.transportPolicies[TransportType.UDP]?.mtu = new
            Log.i("BypassConfig", "MTU changed to $new")
        }
    }"""

new_set_mtu = """    fun setMtu(mtu: Int) {
        val new = mtu.coerceIn(576, 1500)
        if (_currentMtu.value != new) {
            _currentMtu.value = new
            Log.i("BypassConfig", "TUN MTU changed to $new")
        }
    }"""

content = content.replace(old_set_mtu, new_set_mtu)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/BypassConfig.kt", "w") as f:
    f.write(content)
