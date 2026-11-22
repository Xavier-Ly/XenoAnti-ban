# 异客防封（XenoAnti-ban）

光·遇本地环境隔离 Xposed 模块。纯 Java 层实现，APK 内无任何 `.so`，不联网上报，只做本地查询结果的收敛。

- 包名：`com.yikefangfeng.xeno`
- 入口类：`qwq.love.dfy.xy.HookEntry`
- 最小系统：Android 12（minSdk 31）
- 框架：LSPosed / LSPatch（Xposed API 82）

## 它做什么

| 模块 | 覆盖的本地查询 |
| --- | --- |
| `AntiDetect` | 文件探测与目录列举、文件打开、命令执行、包名查询（含 Android 13+ Flags 重载）、进程与服务列表、堆栈、调试状态、系统属性、Build 字段、`/proc`（`FileInputStream` 与 `RandomAccessFile` 两条路径）、maps/mounts/tcp/route/input、全局设置项、框架类加载探测 |
| `FingerprintIsolation` | IMEI、IMSI、ICCID、android_id、序列号、WiFi MAC、蓝牙 MAC、MediaDrm 设备 ID、热点 BSSID、运营商字段、主机名 |
| `InputTrace` | 事件注入标记位、虚拟设备号归一、无障碍服务过滤、输入设备枚举过滤 |
| `NetworkIsolation` | VPN 传输层标记、虚拟网卡、代理属性、系统代理设置项、代理环境变量 |

三条设计约束：

1. 所有替换都是**等长替换**，不改变返回值类型和长度，不返回 `null` 顶替正常值；
2. 文件 / 包名 / 命令一律**精确匹配**，不做包含匹配，游戏自身的目录与文件不碰；
3. 任何一步失败只跳过自己，不影响其余模块和目标应用启动。

## 它做不到什么

- **native 层**：`Os.access`、native `fopen("/proc/self/maps")`、IL2CPP 内部自校验 —— 用户态 Java hook 不参与，需 Shamiko / Zygisk 等配合。
- **服务端按出口 IP 串联多账号**：模块层无法解决，需要每个账号走不同线路。

## 作用域（7 个渠道）

```
com.netease.sky              # 官服
com.netease.sky.bilibili     # B站服
com.netease.sky.huawei       # 华为服
com.netease.sky.vivo         # vivo服
com.netease.sky.aligames     # 九游服
com.netease.sky.m4399        # 4399服
com.tencent.tmgp.eyou.eygy   # 应用宝服
```

## 构建

```bash
./gradlew :app:assembleRelease
```

**release 必须开启混淆**（`app/module.toml` 中 `release.minifyEnabled = true`）：不混淆时模块会产出 59 个 dex，而部分 LSPatch 宿主只加载单个 dex，会导致 `Failed to load class qwq.love.dfy.xy.HookEntry`。混淆后为 1 个 dex，约 0.8 MB。

签名：

```bash
zipalign -p -f 4 app-release-unsigned.apk app-release-aligned.apk
apksigner sign --ks my.jks --ks-key-alias mykey --out app-release-signed.apk app-release-aligned.apk
```

### 混淆规则

`app/proguard-rules.pro` 已包含 Xposed 模块必需规则，其中最容易漏掉的是回调方法名：

```proguard
-keepclassmembers class * extends de.robv.android.xposed.XC_MethodHook {
    protected void beforeHookedMethod(de.robv.android.xposed.XC_MethodHook$MethodHookParam);
    protected void afterHookedMethod(de.robv.android.xposed.XC_MethodHook$MethodHookParam);
}
```

方法名被改名后 override 失效，模块能加载但一个 hook 都不会生效。

## 安装与验证

1. 安装模块 APK；
2. LSPosed：启用模块 → 勾选你实际安装的那个渠道包 → 结束目标进程后重启；LSPatch：修补目标 APK 后安装补丁包；
3. 查看框架日志，应有：

```
[DFY] API ok: framework
[DFY] inject pkg=com.netease.sky proc=... modules=4/4
[DFY] AntiDetect hooks ok=N failed=M
```

`hooks ok` 是真正挂上的 hook 条数，不是「install 没抛异常」。

## 指纹槽位

同机多账号时，在模块 App 的「指纹槽位」里给每个号选一个不同槽位（1~5），整套设备标识随之变化；同一槽位重启后保持不变。槽位通过 `XSharedPreferences` 跨进程读取。

## 目录结构

```
app/src/main/java/qwq/love/dfy/xy/   # 模块逻辑（HookEntry / AntiDetect / FingerprintIsolation / InputTrace / NetworkIsolation / Targets）
app/src/main/java/de/robv/android/xposed/  # 编译期 API 桩（运行时由框架真实实现接管）
app/src/main/assets/xposed_init      # 入口类声明
app/src/main/kotlin/com/yikefangfeng/xeno/MainActivity.kt  # 模块展示页
```

## 免责声明

本项目仅供技术研究与学习，用于在自己拥有控制权的设备上观察系统查询行为。请遵守游戏用户协议与所在地法律法规，因使用本项目产生的任何后果由使用者自行承担。

## 许可

[MIT](LICENSE)
