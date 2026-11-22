package de.robv.android.xposed.callbacks;

/** 编译期桩：加载包回调参数 */
public class XC_LoadPackage {

    public static class LoadPackageParam {
        public String packageName;
        public String processName;
        public ClassLoader classLoader;
        public boolean isFirstApplication;
    }
}
