package de.robv.android.xposed;

/** 编译期桩：反射 Hook 工具，真实实现由框架在运行时注入 */
public final class XposedHelpers {

    private XposedHelpers() {
    }

    public static Object findAndHookMethod(String className, ClassLoader classLoader,
                                           String methodName, Object... parameterTypesAndCallback) {
        return null;
    }

    public static Object findAndHookMethod(Class<?> clazz, String methodName,
                                           Object... parameterTypesAndCallback) {
        return null;
    }

    public static Object findAndHookConstructor(Class<?> clazz,
                                                Object... parameterTypesAndCallback) {
        return null;
    }

    public static Object findAndHookConstructor(String className, ClassLoader classLoader,
                                                Object... parameterTypesAndCallback) {
        return null;
    }

    public static Object getStaticObjectField(Class<?> clazz, String fieldName) {
        return null;
    }

    public static void setStaticObjectField(Class<?> clazz, String fieldName, Object value) {
    }

    public static void setAdditionalInstanceField(Object obj, String key, Object value) {
    }

    public static Object getAdditionalInstanceField(Object obj, String key) {
        return null;
    }
}
