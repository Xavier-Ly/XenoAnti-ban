package de.robv.android.xposed;

import android.util.Log;

/** 编译期桩：真实实现由 LSPosed / Xposed 在运行时注入 */
public final class XposedBridge {

    /** 打包内的 API 桩类标记：HookEntry 靠它自检是否用上了框架真实 API */
    public static final String IMPL = "stub";

    private XposedBridge() {
    }

    public static void log(String text) {
        Log.i("DFY", String.valueOf(text));
    }

    public static void log(Throwable t) {
        Log.e("DFY", "xposed", t);
    }

    public static void hookAllConstructors(Class<?> clazz, XC_MethodHook callback) {
    }
}
