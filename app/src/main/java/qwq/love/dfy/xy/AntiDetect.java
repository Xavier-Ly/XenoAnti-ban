package qwq.love.dfy.xy;

import android.app.ActivityManager;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Build;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

/**
 * 异客防封 —— 本地检测对抗（1.0 版逻辑）
 *
 * 十层覆盖，全部是「游戏拿来扫环境」的只读查询，不改变游戏自身的启动路径：
 *
 *   1. 文件探测      su / magisk / frida / busybox / ksud 这些路径一律报不存在
 *   2. 命令执行      只有直接调用 root 工具才失败，任何 shell、getprop、ps 全部放行
 *   3. 包名探测      Magisk、LSPosed、KernelSU、双开管理器、模块自身全部隐身
 *   4. 调试探测      isDebuggerConnected / waitingForDebugger 恒 false
 *   5. 系统属性      ro.debuggable / ro.secure / ro.build.tags / 验证启动状态全部顶回正常值
 *   6. 模拟器特征    goldfish / ranchu / vbox / nox 等字段换成真机特征
 *   7. 进程服务      跑着的 magiskd / frida-server 不出现在进程列表里
 *   8. 堆栈特征      异常栈、线程栈里翻不到 Xposed / LSPosed / 模块自身
 *   9. /proc 探针    TracerPid 恒 0（这条最常被反调试用）
 *  10. maps 清洗     内存映射里 magisk / riru / zygisk / xposed / frida 的段整段抹掉，
 *                   挂载表同样处理，selinux enforce 顶成 1，tcp 里的 frida 端口行删除
 *
 * 三条自我约束（保证游戏能正常启动）：
 *   · 所有替换都是等长替换，不改变返回值类型、不改变长度、不返回 null 顶替正常值
 *   · 文件 / 包名 / 命令全部精确匹配，绝不做包含匹配，不误伤游戏自己的任何东西
 *   · 游戏自身的数据目录、外部存储、设置页、资源目录、shell 调用一律不碰
 */
public final class AntiDetect {

    private AntiDetect() {}

    /** 防重入，避免 hook 内部再次触发同一条 hook 打转 */
    private static final ThreadLocal<Boolean> BUSY = new ThreadLocal<Boolean>();

    private static final String PROC_KEY = "dfy_proc_path";

    /** hook 成功 / 失败计数：[0]=成功 [1]=失败，用于自检日志 */
    private static final int[] STAT = new int[2];

    /** 热路径缓存：最近一次命中的流对象与路径（身份比较，免掉每次 map 查找） */
    private static volatile Object LAST_STREAM;
    private static volatile String LAST_PATH;

    /** 需要隐身的包名（精确匹配） */
    private static final String[] HIDDEN_PKGS = {
            "com.topjohnwu.magisk",
            "io.github.huskydg.magisk",
            "io.github.vvb2060.magisk",
            "me.weishu.kernelsu",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "de.robv.android.xposed.installer",
            "org.lsposed.manager",
            "org.meowcat.edxposed.manager",
            "com.saurik.substrate",
            "io.va.exposed",
            "org.lsposed.lspatch",
            "com.devadvance.rootcloak",
            "com.formyhm.hideroot",
            "com.amphoras.hidemyroot",
            "com.byapps.byroot",
            "com.lbe.parallel",
            "com.excelliance.dualaid",
            "com.lody.virtual",
            // 本模块自身：APK 包名 + Java 包名，两个都要藏
            "com.yikefangfeng.xeno",
            "qwq.love.dfy.xy"
    };

    /** 系统目录（只在这些目录里按精确文件名过滤） */
    private static final String[] SYS_DIRS = {
            "/system/bin",
            "/system/xbin",
            "/system/sbin",
            "/system/app",
            "/system/priv-app",
            "/sbin",
            "/vendor/bin",
            "/debug_ramdisk",
            "/data/adb",
            "/data/local/bin",
            "/data/local/tmp"
    };

    /** 会被拿来找 root / 框架痕迹的文件名（精确匹配） */
    private static final String[] BAD_FILES = {
            "su", "magisk", "magiskd", "magiskinit", "magiskpolicy",
            "magisk32", "magisk64", "ksud", "busybox",
            "supersu", "superuser", "daemonsu",
            "frida-server", "frida-helper", "frida-server-64"
    };

    /** 完整路径精确命中 */
    private static final String[] BAD_PATHS = {
            "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su-backup",
            "/system/xbin/daemonsu",
            "/system/etc/init.d/99SuperSUDaemon",
            "/su/bin/su",
            "/data/su",
            "/dev/su",
            "/sbin/.magisk",
            "/data/adb/magisk",
            "/data/adb/modules",
            "/data/adb/lspd",
            "/data/magisk",
            "/cache/magisk.log",
            "/init.magisk.rc",
            "/system/etc/init/magisk.rc",
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/system/lib/libfrida-gadget.so",
            "/system/lib64/libfrida-gadget.so"
    };

    /** 堆栈里要抹掉的类名特征 */
    private static final String[] STACK_MARKS = {
            "de.robv.android.xposed",
            "org.lsposed",
            "io.github.lsposed",
            "com.saurik.substrate",
            "com.elderdrivers.riru",
            "qwq.love.dfy.xy"
    };

    /** 进程列表里要隐身的名字特征 */
    private static final String[] HIDDEN_PROC = {
            "magisk", "frida", "xposed", "lspd", "lspatch", "ksud", "shamiko"
    };

    /** 游戏自身目录、外部存储：无条件放行 */
    /** 各渠道服自己的数据目录：由 Targets 统一展开，全部无条件放行 */
    private static final String[] GAME_DIRS = buildGameDirs();

    private static String[] buildGameDirs() {
        List<String> out = new ArrayList<String>();
        for (String p : Targets.PKGS) {
            out.add(S.of("/data/data/", p));
            out.add(S.of("/data/user/0/", p));
            out.add(S.of("/data/user_de/0/", p));
            out.add(S.of("/sdcard/Android/data/", p));
            out.add(S.of("/sdcard/Android/obb/", p));
            out.add(S.of("/storage/emulated/0/Android/data/", p));
            out.add(S.of("/storage/emulated/0/Android/obb/", p));
        }
        return out.toArray(new String[0]);
    }

    /** 外部存储根：这里不再无条件放行，只对「root 工具同名文件」按名字过滤 */
    private static final String[] EXT_DIRS = {
            "/sdcard",
            "/storage/emulated/0",
            "/storage/self/primary",
            "/mnt/sdcard"
    };

    /** 系统属性伪装表 */
    private static final String[] PROP_KEYS = {
            "ro.debuggable",
            "ro.secure",
            "ro.build.tags",
            "ro.build.type",
            "ro.build.selinux",
            "ro.boot.verifiedbootstate",
            "ro.boot.veritymode",
            "ro.boot.flash.locked",
            "ro.boot.vbmeta.device_state",
            "ro.kernel.qemu",
            "ro.boot.qemu",
            "ro.boot.qemuboot",
            "service.adb.root",
            "ro.adb.secure",
            "sys.oem_unlock_allowed",
            "init.svc.magiskd"
    };

    private static final String[] PROP_VALS = {
            "0",
            "1",
            "release-keys",
            "user",
            "1",
            "green",
            "enforcing",
            "1",
            "locked",
            "0",
            "0",
            "0",
            "0",
            "1",
            "0",
            "stopped"
    };

    /** 模拟器特征词（Build 字段命中就换成真机特征） */
    private static final String[] EMU_MARKS = {
            "goldfish", "ranchu", "vbox", "virtualbox", "emulator", "genymotion",
            "bluestacks", "nox", "andy", "ttvm", "droid4x", "sdk_gphone",
            "google_sdk", "vphone", "microvirt"
    };

    /** maps / 挂载表里要整段抹掉的特征 */
    private static final String[] MAP_MARKS = {
            "magisk", "riru", "zygisk", "xposed", "lspd", "lspatch", "shamiko",
            "frida", "sandhook", "/data/adb", "modules.dex", "edxposed",
            "substrate", "libpine", "libepic", "ksud",
            // 模块自身：dex / apk 映射段同样不能留在 maps 里
            "yikefangfeng", "qwq.love.dfy"
    };

    /** /proc/net/tcp 里 frida 默认端口（27042 / 27043 的十六进制） */
    private static final String[] TCP_MARKS = {":69A2", ":69A3"};

    /** /proc/bus/input/devices 里的虚拟输入设备特征（整段抹掉） */
    private static final String[] VIRT_INPUT_MARKS = {
            "uinput", "virtual", "autoclick", "clicker", "vpad", "minitouch",
            "scrcpy", "goldfish", "qemu", "ranchu", "emulator"
    };

    /** /proc/net/route 里的隧道 / 代理网卡行 */
    private static final String[] ROUTE_MARKS = {
            "tun", "tap", "wg", "ppp", "clash", "vpn", "ipsec"
    };

    private static final Pattern TRACER = Pattern.compile("TracerPid:([ \\t]*)(\\d+)");

    /** 系统设置项：adb开关、开发者选项，游戏常直接当环境证据读 */
    private static final String[] HIDDEN_SETTINGS = {
            "adb_enabled",
            "development_settings_enabled"
    };

    public static void install(ClassLoader cl) {
        try { hookFileProbe(); }        catch (Throwable t) { log("file-probe", t); }
        try { hookRuntimeExec(); }      catch (Throwable t) { log("runtime-exec", t); }
        try { hookPackageManager(); }   catch (Throwable t) { log("package-manager", t); }
        try { hookProcessList(); }      catch (Throwable t) { log("process-list", t); }
        try { hookStackTrace(); }       catch (Throwable t) { log("stack-trace", t); }
        try { hookDebugFlag(); }        catch (Throwable t) { log("debug-flag", t); }
        try { hookSystemProperties(); } catch (Throwable t) { log("sys-prop", t); }
        try { hookBuildFields(); }      catch (Throwable t) { log("build-fields", t); }
        try { hookProcRead(); }         catch (Throwable t) { log("proc-read", t); }
        try { hookRunningServices(); }  catch (Throwable t) { log("running-services", t); }
        try { hookGlobalSettings(); }   catch (Throwable t) { log("global-settings", t); }
        try { hookFileOpen(); }         catch (Throwable t) { log("file-open", t); }
        try { hookDirListing(); }       catch (Throwable t) { log("dir-listing", t); }
        try { hookClassLoad(); }        catch (Throwable t) { log("class-load", t); }
        try { hookRandomAccess(); }     catch (Throwable t) { log("random-access", t); }
        try { hookInputDevices(); }     catch (Throwable t) { log("input-devices", t); }
        logStats();
    }

    // ------------------------------------------------------------------
    // 1. 文件探测：只把「明确是 root / 框架痕迹」的路径报成不存在
    // ------------------------------------------------------------------

    private static void hookFileProbe() {
        XC_MethodHook boolHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof Boolean) || !((Boolean) r)) return;
                if (!(param.thisObject instanceof File)) return;
                String path = safePath((File) param.thisObject);
                if (path != null && isBadPath(path)) {
                    param.setResult(Boolean.FALSE);
                }
            }
        };
        guard("java.io.File", "exists", boolHook);
        guard("java.io.File", "isFile", boolHook);
        guard("java.io.File", "isDirectory", boolHook);
        guard("java.io.File", "canRead", boolHook);
        guard("java.io.File", "canExecute", boolHook);
        guard("java.io.File", "canWrite", boolHook);
    }

    /** 直接打开 root / 框架痕迹文件：同样按「不存在」处理 */
    private static void hookFileOpen() {
        XC_MethodHook h = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                if (param.args == null || param.args.length < 1) return;
                Object a0 = param.args[0];
                String path = null;
                if (a0 instanceof File) {
                    path = ((File) a0).getAbsolutePath();
                } else if (a0 instanceof String) {
                    path = (String) a0;
                }
                if (path == null) return;
                if (isBadPathStrict(path)) {
                    throw new java.io.FileNotFoundException(S.of(path, ": open failed: EACCES"));
                }
            }
        };
        try {
            XposedHelpers.findAndHookConstructor(FileInputStream.class, File.class, h);
        } catch (Throwable ignore) {
        }
        try {
            XposedHelpers.findAndHookConstructor(FileInputStream.class, String.class, h);
        } catch (Throwable ignore) {
        }
    }

    /** 目录列举：/system/bin 这类目录里不能列出 su / magisk 这些名字 */
    private static void hookDirListing() {
        XC_MethodHook names = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof String[])) return;
                if (!(param.thisObject instanceof File)) return;
                String dir = safePath((File) param.thisObject);
                if (dir == null || !isSysDir(dir)) return;
                String[] src = (String[]) r;
                List<String> keep = new ArrayList<String>(src.length);
                boolean changed = false;
                for (String name : src) {
                    if (isBadName(name)) {
                        changed = true;
                        continue;
                    }
                    keep.add(name);
                }
                if (changed) param.setResult(keep.toArray(new String[0]));
            }
        };
        XC_MethodHook files = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof File[])) return;
                if (!(param.thisObject instanceof File)) return;
                String dir = safePath((File) param.thisObject);
                if (dir == null || !isSysDir(dir)) return;
                File[] src = (File[]) r;
                List<File> keep = new ArrayList<File>(src.length);
                boolean changed = false;
                for (File f : src) {
                    if (f != null && isBadName(f.getName())) {
                        changed = true;
                        continue;
                    }
                    keep.add(f);
                }
                if (changed) param.setResult(keep.toArray(new File[0]));
            }
        };
        guard("java.io.File", "list", names);
        guard("java.io.File", "listFiles", files);
    }

    private static boolean isSysDir(String dir) {
        for (String sd : SYS_DIRS) {
            if (dir.equals(sd)) return true;
        }
        return false;
    }

    private static boolean isBadName(String name) {
        if (name == null) return false;
        for (String bad : BAD_FILES) {
            if (bad.equals(name)) return true;
        }
        return false;
    }

    /** 加载框架类：Class.forName / ClassLoader.loadClass 一律报类不存在 */
    /** 被 Class.forName / loadClass 探测时要报不存在的框架类前缀 */
    private static final String[] FRAMEWORK_CLASS_MARKS = {
            // 只拦「游戏用来判框架」的经典类名；不碰 LSPosed 自身命名空间，
            // 否则框架内部延迟加载会拿到 CNFE，直接把游戏进程带崩
            "de.robv.android.xposed",
            "com.saurik.substrate",
            "com.elderdrivers.riru"
    };

    /** 加载框架类：Class.forName / ClassLoader.loadClass 一律报类不存在 */
    private static void hookClassLoad() {
        XC_MethodHook h = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object a0 = (param.args != null && param.args.length > 0) ? param.args[0] : null;
                if (a0 instanceof String && isFrameworkClass((String) a0)) {
                    throw new ClassNotFoundException((String) a0);
                }
            }
        };
        guard("java.lang.Class", "forName", h, String.class);
        guard("java.lang.Class", "forName", h, String.class, boolean.class, ClassLoader.class);
        guard("java.lang.ClassLoader", "loadClass", h, String.class);
    }

    private static boolean isFrameworkClass(String name) {
        for (String m : FRAMEWORK_CLASS_MARKS) {
            if (name.startsWith(m)) return true;
        }
        return false;
    }

    /** RandomAccessFile 读 /proc：绕开 FileInputStream 的那条路也堵住 */
    /** RandomAccessFile 读 /proc：绕开 FileInputStream 的那条路也堵住 */
    /** RandomAccessFile 读 /proc：绕开 FileInputStream 的那条路也堵住 */
    private static void hookRandomAccess() {
        XC_MethodHook ctor = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                try {
                    Object a0 = (param.args != null && param.args.length > 0) ? param.args[0] : null;
                    String path = null;
                    if (a0 instanceof File) {
                        path = ((File) a0).getAbsolutePath();
                    } else if (a0 instanceof String) {
                        path = (String) a0;
                    }
                    if (path == null || !isSensitiveProc(path)) return;
                    XposedHelpers.setAdditionalInstanceField(param.thisObject, PROC_KEY, norm(path));
                } catch (Throwable ignore) {
                }
            }
        };
        try {
            XposedHelpers.findAndHookConstructor(RandomAccessFile.class, File.class, String.class, ctor);
        } catch (Throwable ignore) {
        }
        try {
            XposedHelpers.findAndHookConstructor(RandomAccessFile.class, String.class, String.class, ctor);
        } catch (Throwable ignore) {
        }

        XC_MethodHook line = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof String)) return;
                String s = (String) r;
                if (s.length() == 0) return;
                try {
                    Object p = XposedHelpers.getAdditionalInstanceField(param.thisObject, PROC_KEY);
                    if (!(p instanceof String)) return;
                    String path = (String) p;
                    String out;
                    if (path.endsWith("/status")) {
                        out = cleanTracerLine(s);
                    } else if (hitMarks(s, MAP_MARKS) || hitMarks(s, ROUTE_MARKS)
                            || hitMarks(s, TCP_MARKS) || hitMarks(s, VIRT_INPUT_MARKS)) {
                        out = "";
                    } else {
                        return;
                    }
                    if (!out.equals(s)) param.setResult(out);
                } catch (Throwable ignore) {
                }
            }
        };
        try {
            XposedHelpers.findAndHookMethod(RandomAccessFile.class, "readLine", line);
        } catch (Throwable ignore) {
        }
    }

    /** 单行版 TracerPid 归零 */
    private static String cleanTracerLine(String s) {
        Matcher m = TRACER.matcher(s);
        if (!m.find()) return s;
        if ("0".equals(m.group(2))) return s;
        return S.of("TracerPid:", m.group(1), "0");
    }

    /** 输入设备枚举：虚拟 / 注入设备不出现在结果里 */
    private static void hookInputDevices() {
        XC_MethodHook ids = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof int[])) return;
                int[] src = (int[]) r;
                int[] tmp = new int[src.length];
                int n = 0;
                boolean changed = false;
                for (int i = 0; i < src.length; i++) {
                    if (isVirtualDevice(src[i])) {
                        changed = true;
                        continue;
                    }
                    tmp[n] = src[i];
                    n++;
                }
                if (!changed) return;
                int[] out = new int[n];
                System.arraycopy(tmp, 0, out, 0, n);
                param.setResult(out);
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.view.InputDevice", null, "getDeviceIds", ids);
        } catch (Throwable ignore) {
        }

        XC_MethodHook name = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof String)) return;
                if (!hitMarks((String) r, VIRT_INPUT_MARKS)) return;
                param.setResult("gpio-keys");
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.view.InputDevice", null, "getName", name);
        } catch (Throwable ignore) {
        }
    }

    /** 按设备名判断是否为虚拟输入设备 */
    private static boolean isVirtualDevice(int id) {
        try {
            Class<?> c = Class.forName("android.view.InputDevice");
            Object dev = c.getMethod("getDevice", int.class).invoke(null, Integer.valueOf(id));
            if (dev == null) return false;
            Object name = c.getMethod("getName").invoke(dev);
            return (name instanceof String) && hitMarks((String) name, VIRT_INPUT_MARKS);
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * 严格判定：只有「几乎可以确定是 root / 框架痕迹」的路径才允许直接抛异常。
     * 打开文件抛异常是会被上层感知的，判定放宽容易把游戏自己的文件误伤成闪退。
     */
    private static boolean isBadPathStrict(String raw) {
        String p = norm(raw);
        for (String d : GAME_DIRS) {
            if (p.equals(d) || p.startsWith(S.of(d, "/"))) return false;
        }
        for (String bad : BAD_PATHS) {
            if (p.equals(bad)) return true;
        }
        if (p.equals("/data/adb") || p.startsWith("/data/adb/")) return true;
        for (String pkg : HIDDEN_PKGS) {
            if (p.endsWith(S.of("/", pkg))) return true;
            if (p.indexOf(S.of("/", pkg, "-")) >= 0) return true;
        }
        int slash = p.lastIndexOf('/');
        if (slash <= 0) return false;
        String base = p.substring(slash + 1);
        String dir = p.substring(0, slash);
        for (String bad : BAD_FILES) {
            if (!base.equals(bad)) continue;
            for (String sd : SYS_DIRS) {
                if (dir.equals(sd) || dir.startsWith(S.of(sd, "/"))) return true;
            }
        }
        return false;
    }

    private static boolean isBadPath(String raw) {
        String p = norm(raw);

        for (String d : GAME_DIRS) {
            if (p.equals(d) || p.startsWith(S.of(d, "/"))) return false;
        }

        for (String bad : BAD_PATHS) {
            if (p.equals(bad)) return true;
        }

        // 隐身包名的数据 / 安装目录：/data/data/<pkg>、/data/user/0/<pkg>、/data/app/<pkg>-xxx
        for (String pkg : HIDDEN_PKGS) {
            if (p.endsWith(S.of("/", pkg))) return true;
            if (p.indexOf(S.of("/", pkg, "-")) >= 0) return true;
        }

        if (p.equals("/data/adb") || p.startsWith("/data/adb/")) return true;

        int slash = p.lastIndexOf('/');
        if (slash <= 0) return false;
        String base = p.substring(slash + 1);
        String dir = p.substring(0, slash);
        for (String bad : BAD_FILES) {
            if (!base.equals(bad)) continue;
            for (String sd : SYS_DIRS) {
                if (dir.equals(sd) || dir.startsWith(S.of(sd, "/"))) return true;
            }
            for (String ed : EXT_DIRS) {
                if (dir.equals(ed) || dir.startsWith(S.of(ed, "/"))) return true;
            }
        }
        return false;
    }

    private static String safePath(File f) {
        try {
            String p = f.getAbsolutePath();
            return p == null ? null : norm(p);
        } catch (Throwable t) {
            return null;
        }
    }

    private static String norm(String s) {
        String p = s.toLowerCase(Locale.ROOT).replace('\\', '/');
        while (p.endsWith("/") && p.length() > 1) {
            p = p.substring(0, p.length() - 1);
        }
        if (p.indexOf("/./") >= 0) p = p.replace("/./", "/");
        if (p.indexOf("//") >= 0) p = p.replace("//", "/");
        return p;
    }

    // ------------------------------------------------------------------
    // 2. 命令执行：只挡「直接调用 root 工具」，shell / getprop / ps 一律放行
    // ------------------------------------------------------------------

    private static void hookRuntimeExec() {
        XC_MethodHook h = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                String bin = firstToken(param.args);
                if (bin == null) return;
                if (isRootBinary(bin)) {
                    throw new IOException(S.of("Cannot run program \"", bin,
                            "\": error=13, Permission denied"));
                }
            }
        };
        try {
            XposedHelpers.findAndHookMethod("java.lang.Runtime", null, "exec", String.class, h);
        } catch (Throwable ignore) {
        }
        try {
            XposedHelpers.findAndHookMethod("java.lang.Runtime", null, "exec", String[].class, h);
        } catch (Throwable ignore) {
        }
        try {
            XposedHelpers.findAndHookMethod("java.lang.ProcessBuilder", null, "start", h);
        } catch (Throwable ignore) {
        }
    }

    private static String firstToken(Object[] args) {
        if (args == null || args.length == 0) return null;
        Object a0 = args[0];
        try {
            if (a0 instanceof String) {
                String s = ((String) a0).trim();
                int sp = s.indexOf(' ');
                return sp > 0 ? s.substring(0, sp) : s;
            }
            if (a0 instanceof String[]) {
                String[] arr = (String[]) a0;
                return arr.length > 0 ? arr[0] : null;
            }
            if (a0 instanceof List) {
                List<?> l = (List<?>) a0;
                if (l.isEmpty()) return null;
                Object o = l.get(0);
                return o == null ? null : String.valueOf(o);
            }
        } catch (Throwable t) {
            return null;
        }
        return null;
    }

    /** 只认「直接跑 root 工具」这一种写法，绝不牵连 sh -c / getprop / ps */
    private static boolean isRootBinary(String cmd) {
        if (cmd == null) return false;
        String c = norm(cmd.trim());
        int slash = c.lastIndexOf('/');
        String base = slash >= 0 ? c.substring(slash + 1) : c;
        for (String bad : BAD_FILES) {
            if (base.equals(bad)) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // 3. 包名探测
    // ------------------------------------------------------------------

    private static void hookPackageManager() {
        XC_MethodHook single = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object a0 = (param.args != null && param.args.length > 0) ? param.args[0] : null;
                if (a0 instanceof String && isHiddenPkg((String) a0)) {
                    param.setThrowable(new PackageManager.NameNotFoundException((String) a0));
                }
            }
        };
        hookPm("getPackageInfo", single, String.class, int.class);
        hookPm("getApplicationInfo", single, String.class, int.class);
        hookPm("getPackageUid", single, String.class, int.class);
        hookPm("getPackageGids", single, String.class);

        XC_MethodHook listHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof List)) return;
                List<?> src = (List<?>) r;
                List<Object> out = new ArrayList<Object>(src.size());
                boolean changed = false;
                for (Object o : src) {
                    String name = pkgNameOf(o);
                    if (name != null && isHiddenPkg(name)) {
                        changed = true;
                        continue;
                    }
                    out.add(o);
                }
                if (changed) param.setResult(out);
            }
        };
        hookPm("getInstalledPackages", listHook, int.class);
        hookPm("getInstalledApplications", listHook, int.class);
        hookPmFlags(single, listHook);
        try {
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", null,
                    "queryIntentActivities", android.content.Intent.class, int.class, listHook);
        } catch (Throwable ignore) {
        }
        try {
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", null,
                    "queryIntentServices", android.content.Intent.class, int.class, listHook);
        } catch (Throwable ignore) {
        }
    }

    /** Android 13+ 的 Flags 重载：老接口挡住了，新接口同样要挡 */
    private static void hookPmFlags(XC_MethodHook single, XC_MethodHook listHook) {
        try {
            Class<?> pi = Class.forName("android.content.pm.PackageManager$PackageInfoFlags");
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", null,
                    "getPackageInfo", String.class, pi, single);
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", null,
                    "getInstalledPackages", pi, listHook);
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", null,
                    "getPackageUid", String.class, pi, single);
        } catch (Throwable ignore) {
        }
        try {
            Class<?> ai = Class.forName("android.content.pm.PackageManager$ApplicationInfoFlags");
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", null,
                    "getApplicationInfo", String.class, ai, single);
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", null,
                    "getInstalledApplications", ai, listHook);
        } catch (Throwable ignore) {
        }
        try {
            Class<?> ri = Class.forName("android.content.pm.PackageManager$ResolveInfoFlags");
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", null,
                    "queryIntentActivities", android.content.Intent.class, ri, listHook);
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", null,
                    "queryIntentServices", android.content.Intent.class, ri, listHook);
        } catch (Throwable ignore) {
        }
    }

    private static void hookPm(String method, XC_MethodHook cb, Object... types) {
        Object[] args = new Object[types.length + 1];
        System.arraycopy(types, 0, args, 0, types.length);
        args[types.length] = cb;
        try {
            XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager", null,
                    method, args);
        } catch (Throwable ignore) {
        }
    }

    private static String pkgNameOf(Object o) {
        try {
            if (o instanceof PackageInfo) return ((PackageInfo) o).packageName;
            if (o instanceof ApplicationInfo) return ((ApplicationInfo) o).packageName;
            if (o instanceof ResolveInfo) {
                ResolveInfo ri = (ResolveInfo) o;
                if (ri.activityInfo != null) return ri.activityInfo.packageName;
                if (ri.serviceInfo != null) return ri.serviceInfo.packageName;
            }
        } catch (Throwable ignore) {
        }
        return null;
    }

    private static boolean isHiddenPkg(String pkg) {
        if (pkg == null) return false;
        for (String s : HIDDEN_PKGS) {
            if (s.equalsIgnoreCase(pkg)) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // 4. 进程列表：magiskd / frida-server 不出现
    // ------------------------------------------------------------------

    private static void hookProcessList() {
        try {
            XposedHelpers.findAndHookMethod("android.app.ActivityManager", null,
                    "getRunningAppProcesses", new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            if (Boolean.TRUE.equals(BUSY.get())) return;
                            Object r = param.getResult();
                            if (!(r instanceof List)) return;
                            List<?> src = (List<?>) r;
                            List<Object> out = new ArrayList<Object>(src.size());
                            boolean changed = false;
                            for (Object o : src) {
                                String name = null;
                                try {
                                    if (o instanceof ActivityManager.RunningAppProcessInfo) {
                                        name = ((ActivityManager.RunningAppProcessInfo) o).processName;
                                    }
                                } catch (Throwable ignore) {
                                }
                                if (name != null && isHiddenProc(name)) {
                                    changed = true;
                                    continue;
                                }
                                out.add(o);
                            }
                            if (changed) param.setResult(out);
                        }
                    });
        } catch (Throwable ignore) {
        }
    }

    /** 运行中的服务列表：root / 框架相关服务一并隐身 */
    private static void hookRunningServices() {
        try {
            XposedHelpers.findAndHookMethod("android.app.ActivityManager", null,
                    "getRunningServices", int.class, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            if (Boolean.TRUE.equals(BUSY.get())) return;
                            Object r = param.getResult();
                            if (!(r instanceof List)) return;
                            List<?> src = (List<?>) r;
                            List<Object> out = new ArrayList<Object>(src.size());
                            boolean changed = false;
                            for (Object o : src) {
                                String proc = null;
                                String svc = null;
                                try {
                                    if (o instanceof ActivityManager.RunningServiceInfo) {
                                        ActivityManager.RunningServiceInfo si =
                                                (ActivityManager.RunningServiceInfo) o;
                                        proc = si.process;
                                        if (si.service != null) svc = si.service.getClassName();
                                    }
                                } catch (Throwable ignore) {
                                }
                                if ((proc != null && isHiddenProc(proc))
                                        || (svc != null && isHiddenProc(svc))) {
                                    changed = true;
                                    continue;
                                }
                                out.add(o);
                            }
                            if (changed) param.setResult(out);
                        }
                    });
        } catch (Throwable ignore) {
        }
    }

    /**
     * 系统设置项：adb_enabled / development_settings_enabled 一律报未开启。
     * 只精确匹配这两个 key，游戏读其它设置项完全不受影响。
     */
    private static void hookGlobalSettings() {
        XC_MethodHook h = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                if (param.args == null || param.args.length < 2) return;
                Object k = param.args[1];
                if (!(k instanceof String)) return;
                if (!isHiddenSetting((String) k)) return;
                Object r = param.getResult();
                if (r == null) return;
                if (r instanceof Integer) {
                    if (((Integer) r).intValue() == 0) return;
                    param.setResult(Integer.valueOf(0));
                } else if (r instanceof Long) {
                    if (((Long) r).longValue() == 0L) return;
                    param.setResult(Long.valueOf(0L));
                } else if (r instanceof String) {
                    param.setResult("0");
                }
            }
        };
        guard("android.provider.Settings$Global", "getInt", h,
                android.content.ContentResolver.class, String.class);
        guard("android.provider.Settings$Global", "getString", h,
                android.content.ContentResolver.class, String.class);
        guard("android.provider.Settings$Secure", "getInt", h,
                android.content.ContentResolver.class, String.class);
    }

    private static boolean isHiddenSetting(String key) {
        for (String s : HIDDEN_SETTINGS) {
            if (s.equalsIgnoreCase(key)) return true;
        }
        return false;
    }

    private static boolean isHiddenProc(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        for (String m : HIDDEN_PROC) {
            if (n.indexOf(m) >= 0) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // 5. 堆栈清洗
    // ------------------------------------------------------------------

    private static void hookStackTrace() {
        XC_MethodHook h = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof StackTraceElement[])) return;
                StackTraceElement[] src = (StackTraceElement[]) r;
                List<StackTraceElement> keep = null;
                for (int i = 0; i < src.length; i++) {
                    if (isFrameworkFrame(src[i])) {
                        if (keep == null) {
                            keep = new ArrayList<StackTraceElement>(src.length);
                            for (int j = 0; j < i; j++) keep.add(src[j]);
                        }
                    } else if (keep != null) {
                        keep.add(src[i]);
                    }
                }
                if (keep != null) {
                    param.setResult(keep.toArray(new StackTraceElement[0]));
                }
            }
        };
        try {
            XposedHelpers.findAndHookMethod("java.lang.Throwable", null, "getStackTrace", h);
        } catch (Throwable ignore) {
        }
        try {
            XposedHelpers.findAndHookMethod("java.lang.Thread", null, "getStackTrace", h);
        } catch (Throwable ignore) {
        }
    }

    private static boolean isFrameworkFrame(StackTraceElement e) {
        if (e == null) return false;
        String cn = e.getClassName();
        if (cn == null) return false;
        for (String m : STACK_MARKS) {
            if (cn.startsWith(m)) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // 6. 调试状态
    // ------------------------------------------------------------------

    private static void hookDebugFlag() {
        XC_MethodHook off = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                param.setResult(Boolean.FALSE);
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.os.Debug", null,
                    "isDebuggerConnected", off);
        } catch (Throwable ignore) {
        }
        try {
            XposedHelpers.findAndHookMethod("android.os.Debug", null,
                    "waitingForDebugger", off);
        } catch (Throwable ignore) {
        }
    }

    // ------------------------------------------------------------------
    // 7. 系统属性
    // ------------------------------------------------------------------

    private static void hookSystemProperties() {
        XC_MethodHook strHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object a0 = (param.args != null && param.args.length > 0) ? param.args[0] : null;
                if (!(a0 instanceof String)) return;
                Object r = param.getResult();
                if (!(r instanceof String)) return;
                String v = fakeProp((String) a0);
                if (v == null) v = fakeEmuProp((String) a0, (String) r);
                if (v == null) return;
                if (!v.equals(r)) param.setResult(v);
            }
        };
        guard("android.os.SystemProperties", "get", strHook, String.class);
        guard("android.os.SystemProperties", "get", strHook, String.class, String.class);

        XC_MethodHook intHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object a0 = (param.args != null && param.args.length > 0) ? param.args[0] : null;
                if (!(a0 instanceof String)) return;
                String v = fakeProp((String) a0);
                if (v == null) return;
                try {
                    param.setResult(Integer.valueOf(Integer.parseInt(v)));
                } catch (Throwable ignore) {
                }
            }
        };
        guard("android.os.SystemProperties", "getInt", intHook, String.class, int.class);

        XC_MethodHook longHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object a0 = (param.args != null && param.args.length > 0) ? param.args[0] : null;
                if (!(a0 instanceof String)) return;
                String v = fakeProp((String) a0);
                if (v == null) return;
                try {
                    param.setResult(Long.valueOf(Long.parseLong(v)));
                } catch (Throwable ignore) {
                }
            }
        };
        guard("android.os.SystemProperties", "getLong", longHook, String.class, long.class);

        XC_MethodHook boolHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object a0 = (param.args != null && param.args.length > 0) ? param.args[0] : null;
                if (!(a0 instanceof String)) return;
                String v = fakeProp((String) a0);
                if (v == null) return;
                param.setResult(Boolean.valueOf("1".equals(v) || "true".equalsIgnoreCase(v)));
            }
        };
        guard("android.os.SystemProperties", "getBoolean", boolHook, String.class, boolean.class);
    }

    /** 只在这一项的值本身带模拟器特征时才顶掉，真机一个字节都不动 */
    private static String fakeEmuProp(String key, String cur) {
        if (cur == null) return null;
        boolean emuKey = "ro.hardware".equals(key)
                || "ro.boot.hardware".equals(key)
                || "ro.product.board".equals(key)
                || "ro.board.platform".equals(key)
                || "ro.product.cpu.abi".equals(key);
        if (!emuKey) return null;
        String low = cur.toLowerCase(Locale.ROOT);
        for (String m : EMU_MARKS) {
            if (low.indexOf(m) >= 0) return "qcom";
        }
        return null;
    }

    private static String fakeProp(String key) {
        if (key == null) return null;
        // 递归保护：fakeProp 内部会走 FingerprintIsolation，它可能再读系统属性
        if (Boolean.TRUE.equals(BUSY.get())) return null;
        BUSY.set(Boolean.TRUE);
        try {
            return fakePropInner(key);
        } catch (Throwable ignore) {
            return null;
        } finally {
            BUSY.set(Boolean.FALSE);
        }
    }

    private static String fakePropInner(String key) {
        for (int i = 0; i < PROP_KEYS.length; i++) {
            if (PROP_KEYS[i].equals(key)) return PROP_VALS[i];
        }
        // 序列号 / 主机名跟多开实例走，配合指纹隔离
        if ("ro.serialno".equals(key) || "ro.boot.serialno".equals(key)) {
            return FingerprintIsolation.serial();
        }
        if ("net.hostname".equals(key)) {
            return FingerprintIsolation.hostname();
        }
        return null;
    }

    // ------------------------------------------------------------------
    // 8. 模拟器特征
    // ------------------------------------------------------------------

    private static void hookBuildFields() {
        fixBuild("BRAND", "google");
        fixBuild("DEVICE", "redfin");
        fixBuild("MODEL", "Pixel 5");
        fixBuild("MANUFACTURER", "Google");
        fixBuild("PRODUCT", "redfin");
        fixBuild("HARDWARE", "redfin");
        fixBuild("BOARD", "redfin");
        fixBuild("FINGERPRINT",
                "google/redfin/redfin:11/RQ3A.211001.001/7641976:user/release-keys");
        fixExact("TAGS", "test-keys", "release-keys");
        fixExact("TYPE", "userdebug", "user");
        fixExact("TYPE", "eng", "user");
    }

    private static void fixBuild(String field, String good) {
        try {
            Object cur = XposedHelpers.getStaticObjectField(Build.class, field);
            if (!(cur instanceof String)) return;
            String s = ((String) cur).toLowerCase(Locale.ROOT);
            for (String m : EMU_MARKS) {
                if (s.indexOf(m) >= 0) {
                    XposedHelpers.setStaticObjectField(Build.class, field, good);
                    return;
                }
            }
        } catch (Throwable ignore) {
        }
    }

    private static void fixExact(String field, String bad, String good) {
        try {
            Object cur = XposedHelpers.getStaticObjectField(Build.class, field);
            if (!(cur instanceof String)) return;
            if (bad.equalsIgnoreCase((String) cur)) {
                XposedHelpers.setStaticObjectField(Build.class, field, good);
            }
        } catch (Throwable ignore) {
        }
    }

    // ------------------------------------------------------------------
    // 9 + 10. /proc 探针、maps 与挂载表清洗
    //     全部等长替换：不改变读取长度，不改变返回类型，游戏解析不会错位
    // ------------------------------------------------------------------

    private static void hookProcRead() {
        try {
            XposedBridge.hookAllConstructors(FileInputStream.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        Object a0 = (param.args != null && param.args.length > 0) ? param.args[0] : null;
                        String path = null;
                        if (a0 instanceof File) {
                            path = ((File) a0).getAbsolutePath();
                        } else if (a0 instanceof String) {
                            path = (String) a0;
                        }
                        if (path == null) return;
                        if (!isSensitiveProc(path)) return;
                        XposedHelpers.setAdditionalInstanceField(param.thisObject, PROC_KEY, norm(path));
                    } catch (Throwable ignore) {
                    }
                }
            });
        } catch (Throwable t) {
            log("proc-ctor", t);
        }

        XC_MethodHook reader = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof Integer)) return;
                int n = ((Integer) r).intValue();
                if (n <= 0) return;
                try {
                    // 热路径优化：同一路流连续读时用身份比较直接命中，省掉一次 
                    Object self = param.thisObject;
                    String path;
                    if (self == LAST_STREAM) {
                        path = LAST_PATH;
                    } else {
                        Object p = XposedHelpers.getAdditionalInstanceField(self, PROC_KEY);
                        path = (p instanceof String) ? (String) p : null;
                        LAST_STREAM = self;
                        LAST_PATH = path;
                    }
                    if (path == null) return;
                    if (param.args == null || param.args.length < 1) return;
                    if (!(param.args[0] instanceof byte[])) return;
                    byte[] buf = (byte[]) param.args[0];
                    int off = 0;
                    if (param.args.length >= 3
                            && param.args[1] instanceof Integer
                            && param.args[2] instanceof Integer) {
                        off = ((Integer) param.args[1]).intValue();
                        int max = ((Integer) param.args[2]).intValue();
                        if (off < 0 || off + n > buf.length || n > max) return;
                    } else if (n > buf.length) {
                        return;
                    }
                    sanitize(buf, off, n, path);
                } catch (Throwable ignore) {
                }
            }
        };
        try {
            XposedHelpers.findAndHookMethod(FileInputStream.class, "read", byte[].class, reader);
        } catch (Throwable ignore) {
        }
        try {
            XposedHelpers.findAndHookMethod(FileInputStream.class, "read",
                    byte[].class, int.class, int.class, reader);
        } catch (Throwable ignore) {
        }
    }

    private static boolean isSensitiveProc(String raw) {
        String p = norm(raw);
        if (p.startsWith("/sys/fs/selinux/")) return true;
        if (!p.startsWith("/proc/")) return false;
        if (p.endsWith("/status")) return true;
        if (p.endsWith("/maps")) return true;
        if (p.endsWith("/mounts") || p.endsWith("/mountinfo")) return true;
        if (p.indexOf("/net/tcp") >= 0) return true;
        if (p.indexOf("/net/route") >= 0) return true;
        if (p.equals("/proc/bus/input/devices")) return true;
        return false;
    }

    private static void sanitize(byte[] buf, int off, int len, String path) {
        String s = new String(buf, off, len, java.nio.charset.Charset.forName("ISO-8859-1"));
        String out;
        if (path.startsWith("/sys/fs/selinux/")) {
            out = s.replace('0', '1');
        } else if (path.endsWith("/status")) {
            out = cleanTracer(s);
        } else if (path.endsWith("/bus/input/devices")) {
            out = blockClean(s, VIRT_INPUT_MARKS);
        } else if (path.indexOf("/net/route") >= 0) {
            out = blankLines(s, ROUTE_MARKS);
        } else if (path.indexOf("/net/tcp") >= 0) {
            out = blankLines(s, TCP_MARKS);
        } else if (path.endsWith("/maps")) {
            out = blankLines(s, MAP_MARKS);
        } else {
            out = blankLines(s, MAP_MARKS);
        }
        if (out.equals(s)) return;
        byte[] b = out.getBytes(java.nio.charset.Charset.forName("ISO-8859-1"));
        int n = Math.min(b.length, len);
        System.arraycopy(b, 0, buf, off, n);
        for (int i = n; i < len; i++) buf[off + i] = ' ';
    }

    /** TracerPid 数字位替换为 0，长度保持不变 */
    private static String cleanTracer(String s) {
        Matcher m = TRACER.matcher(s);
        StringBuffer sb = new StringBuffer(s.length() + 8);
        boolean changed = false;
        while (m.find()) {
            String ws = m.group(1);
            String digits = m.group(2);
            if ("0".equals(digits)) continue;
            StringBuilder rep = new StringBuilder(16);
            rep.append("TracerPid:").append(ws);
            for (int i = 0; i < digits.length() - 1; i++) rep.append(' ');
            rep.append('0');
            m.appendReplacement(sb, Matcher.quoteReplacement(rep.toString()));
            changed = true;
        }
        if (!changed) return s;
        m.appendTail(sb);
        return sb.toString();
    }

    /** 命中特征的行整行空白化，保留换行与总长度 */
    private static String blankLines(String s, String[] marks) {
        int n = s.length();
        StringBuilder sb = null;
        int start = 0;
        while (start < n) {
            int nl = s.indexOf('\n', start);
            int end = (nl < 0) ? n : nl;
            String line = s.substring(start, end);
            if (hitMarks(line, marks)) {
                if (sb == null) {
                    sb = new StringBuilder(n);
                    sb.append(s, 0, start);
                }
                for (int i = 0; i < line.length(); i++) sb.append(' ');
                if (nl >= 0) sb.append('\n');
            } else if (sb != null) {
                sb.append(line);
                if (nl >= 0) sb.append('\n');
            }
            start = (nl < 0) ? n : nl + 1;
        }
        return sb == null ? s : sb.toString();
    }

    /**
     * 按「空行分段」清洗：命中特征的整段抹成空白，换行与总长度都不变。
     * 用于 /proc/bus/input/devices —— 一个虚拟设备占一整段（Name/Handlers/EV 位图），
     * 只抹 name 行会留下残段，反而更可疑。
     */
    private static String blockClean(String s, String[] marks) {
        int n = s.length();
        int start = 0;
        StringBuilder sb = null;
        while (start < n) {
            int sep = s.indexOf("\n\n", start);
            int segEnd = (sep < 0) ? n : sep + 1;
            String seg = s.substring(start, segEnd);
            if (seg.length() > 0 && hitMarks(seg, marks)) {
                if (sb == null) {
                    sb = new StringBuilder(n);
                    sb.append(s, 0, start);
                }
                for (int i = 0; i < seg.length(); i++) {
                    sb.append(seg.charAt(i) == '\n' ? '\n' : ' ');
                }
            } else if (sb != null) {
                sb.append(seg);
            }
            start = segEnd;
        }
        return sb == null ? s : sb.toString();
    }

    private static boolean hitMarks(String line, String[] marks) {
        if (line.length() == 0) return false;
        String low = line.toLowerCase(Locale.ROOT);
        for (String m : marks) {
            if (low.indexOf(m.toLowerCase(Locale.ROOT)) >= 0) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // 工具
    // ------------------------------------------------------------------

    private static void guard(String cls, String method, XC_MethodHook cb, Object... types) {
        Object[] args = new Object[types.length + 1];
        System.arraycopy(types, 0, args, 0, types.length);
        args[types.length] = cb;
        try {
            XposedHelpers.findAndHookMethod(cls, null, method, args);
            STAT[0]++;
        } catch (Throwable ignore) {
            STAT[1]++;
        }
    }

    private static void log(String tag, Throwable t) {
        try {
            XposedBridge.log(S.of("[DFY] ", tag, " skip: ", t));
        } catch (Throwable ignore) {
        }
    }

    /** 真正生效的 hook 条数，供 HookEntry 汇总 */
    static int okHooks() {
        return STAT[0];
    }

    static int failedHooks() {
        return STAT[1];
    }

    private static void logStats() {
        try {
            XposedBridge.log(S.of("[DFY] AntiDetect hooks ok=", STAT[0], " failed=", STAT[1]));
        } catch (Throwable ignore) {
        }
    }
}
