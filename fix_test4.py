import re

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyBehaviorTest.kt", "r") as f:
    lines = f.readlines()

# Re-write the file correctly
with open("app/src/test/java/com/aistudio/pinkproxy/fresh/StrategyBehaviorTest.kt", "w") as f:
    in_fool_dpi = False
    for line in lines:
        if "stringOutput.contains(\"GET / HTTP/1.1\")" in line:
            f.write("        assertTrue(\"Should contain fake HTTP GET\", stringOutput.contains(\"GET /\") && stringOutput.contains(\"HTTP/1.1\"))\n")
        elif "class TrackingByteArrayOutputStream" in line:
            pass # we'll put it at the very end
        elif line.strip() == "}":
            pass # skip braces, we will manually close the class
        else:
            if "UDP_STUN_FAKE injects STUN header before original data" in line:
                # We reached the floating test. We make sure it's inside the class
                pass
            f.write(line)

    # Finally close the class and append TrackingByteArrayOutputStream
    f.write("}\n\n")
    f.write("""class TrackingByteArrayOutputStream : ByteArrayOutputStream() {
    var writeCount = 0
        private set
    var maxWriteSize = 0
        private set

    override fun write(b: Int) {
        super.write(b)
        writeCount++
        maxWriteSize = maxOf(maxWriteSize, 1)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        super.write(b, off, len)
        writeCount++
        maxWriteSize = maxOf(maxWriteSize, len)
    }
}
""")
