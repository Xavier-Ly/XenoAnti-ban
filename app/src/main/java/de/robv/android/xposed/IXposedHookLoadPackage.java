package de.robv.android.xposed;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * 编译期桩接口：真实实现由 LSPosed / EdXposed 在运行时注入到目标进程的 boot classpath。
 * 模块 APK 内保留同名类，运行时父加载器优先，实际生效的是框架提供的实现。
 */
public interface IXposedHookLoadPackage {

    void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable;
}
