package de.robv.android.xposed;

/** 编译期桩：真实实现由框架在运行时注入（LSPosed 支持跨进程读模块 App 的 SharedPreferences） */
public final class XSharedPreferences {

    public XSharedPreferences(String packageName, String prefFileName) {
    }

    public XSharedPreferences(String packageName) {
    }

    public void reload() {
    }

    public boolean getBoolean(String key, boolean defValue) {
        return defValue;
    }

    public int getInt(String key, int defValue) {
        return defValue;
    }

    public long getLong(String key, long defValue) {
        return defValue;
    }

    public float getFloat(String key, float defValue) {
        return defValue;
    }

    public String getString(String key, String defValue) {
        return defValue;
    }
}
