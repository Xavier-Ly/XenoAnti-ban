package qwq.love.dfy.xy;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * 异客防封 —— 模块入口
 *
 * 作用域：com.netease.sky（光·遇）
 * 功能：屏蔽游戏端的本地环境检测（root / 框架 / 调试 / 多开 / 模拟器 / 设备指纹）
 *
 * 日志标签统一为 [DFY]，可在 LSPosed 日志里直接搜索验证注入是否成功：
 *   [DFY] API ok: framework                     框架 API 正常
 *   [DFY] inject pkg=com.netease.sky proc=...   已进入游戏进程
 *   [DFY] hooked into com.netease.sky modules=4/4  四个子模块全部装上
 */
public class HookEntry implements IXposedHookLoadPackage {

    /** 目标包名由 Targets 统一维护（含各渠道服） */

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (lpparam == null) return;
        if (!Targets.isTarget(lpparam.packageName)) return;

        ClassLoader cl = lpparam.classLoader;

        logApiState();
        XposedBridge.log(S.of("[DFY] inject pkg=", lpparam.packageName,
                " proc=", lpparam.processName));

        int ok = 0;
        try {
            AntiDetect.install(cl);
            ok++;
        } catch (Throwable t) {
            XposedBridge.log(S.of("[DFY] AntiDetect failed: ", t));
        }

        try {
            FingerprintIsolation.install(cl);
            ok++;
        } catch (Throwable t) {
            XposedBridge.log(S.of("[DFY] FingerprintIsolation failed: ", t));
        }

        try {
            InputTrace.install(cl);
            ok++;
        } catch (Throwable t) {
            XposedBridge.log(S.of("[DFY] InputTrace failed: ", t));
        }

        try {
            NetworkIsolation.install(cl);
            ok++;
        } catch (Throwable t) {
            XposedBridge.log(S.of("[DFY] NetworkIsolation failed: ", t));
        }

        XposedBridge.log(S.of("[DFY] hooked into ", lpparam.packageName,
                " modules=", ok, "/4 hooksOk=", AntiDetect.okHooks(),
                " hooksFailed=", AntiDetect.failedHooks()));
    }

    /**
     * 自检：确认运行时用的是框架真实 API，而不是 APK 里打包的编译桩。
     * 若日志出现 WARN，说明框架 API 没注入，任何 hook 都不会生效。
     */
    private static void logApiState() {
        try {
            XposedBridge.class.getDeclaredField("IMPL");
            XposedBridge.log("[DFY] WARN 打包内 API 桩生效：框架 API 未注入，hook 不会生效");
        } catch (NoSuchFieldException e) {
            XposedBridge.log("[DFY] API ok: framework");
        } catch (Throwable ignore) {
        }
    }
}
