with open('app/src/main/java/com/aistudio/pinkproxy/fresh/MainActivity.kt', 'r') as f:
    content = f.read()

import re

ui_addition = """
                    // SOCKS5 Badge
                    Surface(
                        color = Color(0xFFCE93D8).copy(alpha = 0.1f),
                        shape = RoundedCornerShape(16.dp),
                        border = BorderStroke(1.dp, Color(0xFFCE93D8).copy(alpha = 0.3f)),
                        modifier = Modifier.padding(start = 8.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = Color(0xFFCE93D8),
                                modifier = Modifier.size(12.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                text = "SOCKS5: 127.0.0.1:18080",
                                color = Color(0xFFCE93D8),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Medium
                            )
                        }
                    }
"""

content = re.sub(
    r'(// Autopilot Badge.*?</Surface>)',
    r'\1\n' + ui_addition.strip(),
    content,
    flags=re.DOTALL
)

with open('app/src/main/java/com/aistudio/pinkproxy/fresh/MainActivity.kt', 'w') as f:
    f.write(content)
