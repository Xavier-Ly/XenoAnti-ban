# ============================================================
#  LSPatch / LSPosed 模块必需规则
#  说明：模块当前 minifyEnabled=false，但一旦开启 R8/混淆
#        缺了下面任意一条，都会出现「Failed to load class
#        xxx.HookEntry」或「hook 挂上了但回调不触发」。
# ============================================================

# 1) 入口类：assets/xposed_init 里写的类名必须原样保留
-keep class qwq.love.dfy.xy.HookEntry { *; }
-keep class * implements de.robv.android.xposed.IXposedHookLoadPackage { *; }
-keep class * implements de.robv.android.xposed.IXposedHookZygoteInit { *; }
-keep class * implements de.robv.android.xposed.IXposedHookInitPackageResources { *; }

# 2) 编译期 API 桩：类名与成员名不能被改，否则运行时和框架真实 API 对不上
-keep class de.robv.android.xposed.** { *; }
-dontwarn de.robv.android.xposed.**

# 3) 回调方法名必须保留
#    框架是按方法名 beforeHookedMethod / afterHookedMethod 回调的，
#    一旦被改名，override 就失效 —— 表现是「注入成功但完全没效果」。
-keepclassmembers class * extends de.robv.android.xposed.XC_MethodHook {
    protected void beforeHookedMethod(de.robv.android.xposed.XC_MethodHook$MethodHookParam);
    protected void afterHookedMethod(de.robv.android.xposed.XC_MethodHook$MethodHookParam);
}

# 4) 模块自身的类全量保留（体积不大，避免漏网）
-keep class qwq.love.dfy.xy.** { *; }

# 5) 保留注解/泛型签名/内部类信息
-keepattributes *Annotation*, Signature, InnerClasses, EnclosingMethod, Exceptions

# 6) 模块不需要被 shrink 掉入口相关的一切
