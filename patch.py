import re

# We will apply changes ONE BY ONE and compile between each one.

# 1. Decay logic in StrategyState (Clean regex replacement)
with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt', 'r') as f:
    text = f.read()

decay_old = '''
            if (decayFactor < 0.95) {
                weightedSuccess.set((weightedSuccess.get() * decayFactor).toLong())
                weightedFailure.set((weightedFailure.get() * decayFactor).toLong())
            }
'''
decay_new = '''
            if (decayFactor < 0.95) {
                weightedSuccess.set((weightedSuccess.get() * decayFactor).toLong())
                weightedFailure.set((weightedFailure.get() * decayFactor).toLong())
                sampleCount.set((sampleCount.get() * decayFactor).toInt())
                successCount.set((successCount.get() * decayFactor).toInt())
                failureCount.set((failureCount.get() * decayFactor).toInt())
                verifiedSuccessCount.set((verifiedSuccessCount.get() * decayFactor).toInt())
            }
'''
text = text.replace(decay_old.strip(), decay_new.strip())

reset_old = '''
                state.weightedFailure.set((state.weightedFailure.get() * 0.1).toLong()) // 90% decay on failures
                state.weightedSuccess.set((state.weightedSuccess.get() * 0.5).toLong()) // 50% decay on successes
                state.failureCount.set(0)
'''
reset_new = '''
                state.weightedFailure.set((state.weightedFailure.get() * 0.1).toLong()) // 90% decay on failures
                state.weightedSuccess.set((state.weightedSuccess.get() * 0.5).toLong()) // 50% decay on successes
                state.sampleCount.set((state.sampleCount.get() * 0.3).toInt())
                state.successCount.set((state.successCount.get() * 0.5).toInt())
                state.verifiedSuccessCount.set((state.verifiedSuccessCount.get() * 0.5).toInt())
                state.failureCount.set(0)
'''
text = text.replace(reset_old.strip(), reset_new.strip())

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/StrategyState.kt', 'w') as f:
    f.write(text)
