# 更新日志

本文件由每次 Release 引用，格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [3.0.2] - 2026-11-23

### 修复

- CI 工作流 `.github/workflows/android-release.yml` 中 `setup-gradle` 步骤重复声明 `with:`，导致 GitHub 判定工作流文件非法、job 未进入任何步骤即失败
- `versionCode` / `versionName` 在 `module.toml` 与 `build.gradle.kts` 中不一致（10/3.0.0 vs 11/3.0.1），已统一为 12/3.0.2

## [3.0.1] - 2026-11-23

### 修复

- **LSPatch 加载失败（ClassNotFoundException: qwq.love.dfy.xy.HookEntry）**
  - 补齐 `proguard-rules.pro`：入口类、Xposed API 桩、`XC_MethodHook` 回调方法名全部 keep
  - `release.minifyEnabled` 改为 `true`，产出**单 dex** 包（此前未混淆时有 59 个 dex，LSPatch 只加载 dex0）
  - 实测：0.8 MB / 1 dex / 入口类未被改名 / 回调方法名保留
- `fakeProp()` 增加重入保护，修掉系统属性 hook 与指纹初始化互递归导致的 `StackOverflowError`
- `FileInputStream` 打开文件改用 `isBadPathStrict()` 判定，避免把游戏自己的文件误判成 root 痕迹而抛异常闪退
- `Class.forName` 拦截名单收窄，不再拦 LSPosed 自身命名空间与本模块类名（会导致框架侧崩溃）

### 变更

- 作用域支持 7 个渠道包（官服 / B站 / 华为 / vivo / 九游 / 4399 / 应用宝），数据目录豁免同步展开
- 新增「指纹槽位」1~5 可选，切换槽位整套设备标识随之改变
- 「模块版本」改为运行时读取 `PackageManager`，与本地 APK 版本一致
- 新增版本检测：`GET /api/app/version`，有新版本弹窗（版本号 / 版本名 / 更新说明 / 下载跳转），无更新轻提示

## [3.0.0] - 2026-11-02

### 新增

- 首次发布。文件与 `/proc` 读取清洗、包管理与系统属性收敛、进程与被装应用列表过滤、输入设备与触摸事件语义修正
- 设备指纹隔离：IMEI / IMSI / ICCID / android_id / 序列号 / MAC / 蓝牙地址 / MediaDrm / WiFi BSSID 按实例派生
- 网络出口清洗：代理环境变量、HTTP 代理、路由表相关读取
- 构建期 API 桩（`de.robv.android.xposed.*`），可脱离框架单独编译
