import re

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/PerFlowStrategyIsolationTest.kt", "r") as f:
    content = f.read()

replacement = """
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class PerFlowStrategyIsolationTest {
"""
content = re.sub(
    r'import kotlinx\.coroutines\.runBlocking\nimport org\.junit\.Assert\.assertEquals\nimport org\.junit\.Before\nimport org\.junit\.Test\n\nclass PerFlowStrategyIsolationTest \{',
    replacement.lstrip('\n'),
    content
)

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/PerFlowStrategyIsolationTest.kt", "w") as f:
    f.write(content)
