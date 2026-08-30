import re

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyTileService.kt', 'r') as f:
    content = f.read()

content = content.replace('''        listenJob = scope.launch {
            PinkVpnService.isRunning.collectLatest { running ->
                updateTile(running)
            }
        }''', '''        listenJob = scope.launch {
            kotlinx.coroutines.flow.combine(
                PinkVpnService.isRunning,
                BypassConfig.strategy
            ) { running, strat ->
                Pair(running, strat)
            }.collectLatest { (running, strat) ->
                updateTile(running, strat.name)
            }
        }''')

content = content.replace('''    private fun updateTile(isActive: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (isActive) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "PinkProxy"
        tile.subtitle = if (isActive) "Active" else "Inactive"
        tile.updateTile()
    }''', '''    private fun updateTile(isActive: Boolean, strat: String = "Active") {
        val tile = qsTile ?: return
        tile.state = if (isActive) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = "PinkProxy"
        tile.subtitle = if (isActive) strat else "Inactive"
        tile.updateTile()
    }''')

content = content.replace('updateTile(PinkVpnService.isRunning.value)', 'updateTile(PinkVpnService.isRunning.value, BypassConfig.strategy.value.name)')

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/PinkProxyTileService.kt', 'w') as f:
    f.write(content)
