import java.lang.reflect.Method;
public class TestReflection {
    public static void main(String[] args) {
        try {
            Class<?> osClass = Class.forName("android.system.Os");
            for (Method m : osClass.getMethods()) {
                if (m.getName().toLowerCase().contains("getsockopt")) {
                    System.out.println(m.getName());
                }
            }
        } catch (Exception e) {}
    }
}
