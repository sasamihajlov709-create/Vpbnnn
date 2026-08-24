sed -i '232,238c\
        // Use global average score as a weak prior for auto-tuner (max 10% weight)\
        val globalAverageMean = getAverageScore(strategy) / 1000.0\
        val priorWeight = 0.1 * (1.0 - confidence).coerceAtLeast(0.0)\
        val blendedMean = (mean * (1.0 - priorWeight)) + (globalAverageMean * priorWeight)' app/src/main/java/com/aistudio/pinkproxy/fresh/DpiStrategySelector.kt
