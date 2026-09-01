import re

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/cronet/CronetEngineProvider.kt", "r") as f:
    content = f.read()

old_logic = """                                // Strict priority: Play Services -> App Packaged -> Fallback
                if (isPlayServicesAvailable) {
                    val playServicesProvider = providers.find { it.name == CronetProvider.PROVIDER_NAME_APP_PACKAGED }
                    if (playServicesProvider != null) { 
                         builder = playServicesProvider.createBuilder()
                         Log.i(TAG, "Using Play Services Cronet provider.")
                    }
                }
                
                if (builder == null) {
                    val fallbackProvider = providers.find { it.name == CronetProvider.PROVIDER_NAME_FALLBACK }
                    if (fallbackProvider != null) {
                        builder = fallbackProvider.createBuilder()
                        Log.i(TAG, "Using Cronet Fallback provider.")
                    } else {
                        builder = CronetEngine.Builder(context)
                        Log.i(TAG, "Using default Cronet Builder.")
                    }
                }"""

new_logic = """                // Strict priority: Play Services -> App Packaged -> Fallback
                val playServicesProvider = providers.find { it.name == CronetProviderInstaller.PROVIDER_NAME }
                val appPackagedProvider = providers.find { it.name == CronetProvider.PROVIDER_NAME_APP_PACKAGED }
                val fallbackProvider = providers.find { it.name == CronetProvider.PROVIDER_NAME_FALLBACK }
                
                val bestProvider = playServicesProvider?.takeIf { isPlayServicesAvailable && it.isEnabled } 
                    ?: appPackagedProvider?.takeIf { it.isEnabled } 
                    ?: fallbackProvider?.takeIf { it.isEnabled }
                
                if (bestProvider != null) {
                    builder = bestProvider.createBuilder()
                    Log.i(TAG, "Using Cronet provider: ${bestProvider.name}")
                } else {
                    builder = CronetEngine.Builder(context)
                    Log.i(TAG, "Using default Cronet Builder.")
                }"""

content = content.replace(old_logic, new_logic)

with open("app/src/main/java/com/aistudio/pinkproxy/fresh/cronet/CronetEngineProvider.kt", "w") as f:
    f.write(content)

