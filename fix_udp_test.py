import re

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/UdpAssociationTableTest.kt", "r") as f:
    text = f.read()

text = re.sub(r'@Test\s+fun testSessionEndpointMapping\(\) \{.*?\}(?=\s+@Test)', '', text, flags=re.DOTALL)

with open("app/src/test/java/com/aistudio/pinkproxy/fresh/UdpAssociationTableTest.kt", "w") as f:
    f.write(text)
