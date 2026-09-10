import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'r') as f:
    content = f.read()

# Add vpnStartupCoordinator initialization
content = content.replace(
    'private var proxyServer: PinkProxyServer? = null',
    '''private var proxyServer: PinkProxyServer? = null
    private lateinit var vpnStartupCoordinator: VpnStartupCoordinator'''
)

content = content.replace(
    'vpnTunnelManager = VpnTunnelManager(this)',
    '''vpnTunnelManager = VpnTunnelManager(this)
        vpnStartupCoordinator = VpnStartupCoordinator(
            vpnService = this,
            vpnTunnelManager = vpnTunnelManager!!,
            transportEngineCoordinator = transportEngineCoordinator,
            recoveryCoordinator = recoveryCoordinator,
            healthMonitor = healthMonitor!!
        )'''
)

# Replace startVpnInternal
start_internal_pattern = re.compile(r'private suspend fun startVpnInternal\(\) = withContext\(ProxyDispatcher\.io\) \{.*?\}\n', re.DOTALL)
replacement = '''private suspend fun startVpnInternal() = withContext(ProxyDispatcher.io) {
        if (_isRunning.value) return@withContext
        isStopping = false
        startDynamicNotification()

        val session = VpnSessionManager.currentSession ?: return@withContext
        session.controlPlaneScope.launch {
            com.aistudio.pinkproxy.fresh.cronet.CronetEngineProvider.initialize(this@PinkVpnService)
        }

        val success = vpnStartupCoordinator.startVpn(
            proxyPort = PROXY_PORT,
            proxySecret = proxySecret,
            session = session,
            isExcludeMode = isExcludeMode,
            selectedPackages = selectedPackages,
            onProxyServerStarted = { newProxy -> proxyServer = newProxy }
        )

        if (success) {
            _isRunning.value = true
            startSessionWarmup()
        } else {
            _isRunning.value = false
            stopVpnInternal()
        }
    }
'''
content = start_internal_pattern.sub(replacement, content, count=1)

# Remove the three helper methods
extract_ips_pattern = re.compile(r'private fun extractIpsFromDnsUrl.*?\n    \}\n', re.DOTALL)
content = extract_ips_pattern.sub('', content, count=1)

local_probe_pattern = re.compile(r'private suspend fun performLocalSocksHealthProbe.*?\}\n', re.DOTALL)
content = local_probe_pattern.sub('', content, count=1)

data_probe_pattern = re.compile(r'private suspend fun performDataPlaneHealthProbe.*?\}\n', re.DOTALL)
content = data_probe_pattern.sub('', content, count=1)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkVpnService.kt', 'w') as f:
    f.write(content)
