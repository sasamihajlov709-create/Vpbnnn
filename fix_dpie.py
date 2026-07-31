with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'r') as f:
    text = f.read()

import re
old_save = """    private fun saveScores(context: android.content.Context) {
        val prefs = context.getSharedPreferences("dpi_engine_scores", android.content.Context.MODE_PRIVATE)
        val editor = prefs.edit()
        strategyScores.forEach { (cat, scores) ->
            scores.forEach { (strat, score) ->
                editor.putInt("${cat.name}_${strat.name}", score.get())
            }
        }
        editor.apply()
    }"""

new_save = """    private fun saveScores(context: android.content.Context) {
        val prefs = context.getSharedPreferences("dpi_engine_scores", android.content.Context.MODE_PRIVATE)
        val editor = prefs.edit()
        strategyScores.forEach { (cat, scores) ->
            scores.forEach { (strat, score) ->
                editor.putInt("${cat.name}_${strat.name}", score.get())
            }
        }
        networkStrategyMemory.forEach { (netType, catMap) ->
            catMap.forEach { (cat, strat) ->
                editor.putString("netmem_${netType}_${cat.name}", strat.name)
            }
        }
        editor.apply()
    }"""

old_load = """    private fun loadScores(context: android.content.Context) {
        val prefs = context.getSharedPreferences("dpi_engine_scores", android.content.Context.MODE_PRIVATE)
        strategyScores.forEach { (cat, scores) ->
            scores.forEach { (strat, score) ->
                val saved = prefs.getInt("${cat.name}_${strat.name}", -1)
                if (saved != -1) score.set(saved)
            }
        }
    }"""

new_load = """    private fun loadScores(context: android.content.Context) {
        val prefs = context.getSharedPreferences("dpi_engine_scores", android.content.Context.MODE_PRIVATE)
        strategyScores.forEach { (cat, scores) ->
            scores.forEach { (strat, score) ->
                val saved = prefs.getInt("${cat.name}_${strat.name}", -1)
                if (saved != -1) score.set(saved)
            }
        }
        prefs.all.keys.filter { it.startsWith("netmem_") }.forEach { key ->
            val parts = key.removePrefix("netmem_").split("_", limit = 2)
            if (parts.size == 2) {
                val netType = parts[0]
                val catName = parts[1]
                val stratName = prefs.getString(key, null)
                if (stratName != null) {
                    try {
                        val cat = HostCategory.valueOf(catName)
                        val strat = BypassStrategy.valueOf(stratName)
                        val catMap = networkStrategyMemory.getOrPut(netType) { ConcurrentHashMap() }
                        catMap[cat] = strat
                    } catch (e: Throwable) {}
                }
            }
        }
    }"""

text = text.replace(old_save, new_save)
text = text.replace(old_load, new_load)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/DpiEngine.kt', 'w') as f:
    f.write(text)
