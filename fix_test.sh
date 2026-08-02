sed -i -e 's/BypassConfig.getScore(BypassStrategy.SNI_SPLIT)/DpiEngine.getAverageScore(BypassStrategy.SNI_SPLIT).toInt()/g' app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyRankingTest.kt
