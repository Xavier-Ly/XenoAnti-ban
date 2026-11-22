package qwq.love.dfy.xy;

import java.lang.reflect.Method;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;

/**
 * 异客防封 —— 网络出口特征（VPN / 代理 / 虚拟网卡）
 *
 * 说明清楚边界：**服务端按出口 IP 把多个账号串起来这件事，模块层做不到**，
 * 那要靠每个账号走不同出口（独立线路 / 代理池 / 不同网络）。本模块解决的是
 * 「本地把代理、VPN、虚拟网卡的特征扫出来」这一半：
 *
 *   1. VPN 传输层   NetworkCapabilities.hasTransport(TRANSPORT_VPN) 恒 false
 *   2. 虚拟网卡     NetworkInterface 列表里 tun / tap / wg / ppp / ipsec 这些接口不出现
 *   3. 代理属性     System.getProperty 里的 http/https/socks 代理字段返回 null
 *   4. 代理设置项   Settings.Global 里的 http_proxy / pac 等条目一并收敛
 * 外加 AntiDetect 侧的 /proc/net/route 清洗（tun / wg 路由行抹掉）
 *
 * 自我约束：
 *   · 只影响「查询结果」，不改真实网络行为 —— 该走代理还是走代理，游戏不会因此断网
 *   · 只按精确前缀识别虚拟网卡，wlan0 / rmnet_data0 / eth0 这些真实接口一律放行
 *   · 原值为 null 时不动，不凭空造值
 */
public final class NetworkIsolation {

    private NetworkIsolation() {}

    private static final ThreadLocal<Boolean> BUSY = new ThreadLocal<Boolean>();

    /** NetworkCapabilities.TRANSPORT_VPN */
    private static final int TRANSPORT_VPN = 4;

    /** 虚拟 / 隧道网卡前缀（精确前缀，避免误伤真实接口） */
    private static final String[] VIRT_PREFIX = {
            "tun", "tap", "wg", "ppp", "ipsec", "utun", "clash", "vpn", "tproxy"
    };

    /** 代理相关系统属性 */
    private static final String[] PROXY_KEYS = {
            "http.proxyHost", "http.proxyPort",
            "https.proxyHost", "https.proxyPort",
            "socksProxyHost", "socksProxyPort",
            "java.net.useSystemProxies"
    };

    /** Settings.Global 里的代理条目 */
    private static final String[] PROXY_SETTINGS = {
            "http_proxy",
            "global_http_proxy_host",
            "global_http_proxy_port",
            "global_http_proxy_exclusion_list",
            "global_proxy_pac_url",
            "https_proxy", "socks_proxy", "all_proxy"
    };

    public static void install(ClassLoader cl) {
        try { hookVpnTransport(); } catch (Throwable ignore) {}
        try { hookNetworkInterfaces(); } catch (Throwable ignore) {}
        try { hookProxyProps(); } catch (Throwable ignore) {}
        try { hookGlobalProxy(); } catch (Throwable ignore) {}
        try { hookLinkProxy(); } catch (Throwable ignore) {}
        try { hookProxyEnv(); } catch (Throwable ignore) {}
    }

    // ------------------------------------------------------------------
    // 1. VPN 传输层
    // ------------------------------------------------------------------

    private static void hookVpnTransport() {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                if (param.args == null || param.args.length < 1) return;
                Object a0 = param.args[0];
                if (!(a0 instanceof Integer)) return;
                if (((Integer) a0).intValue() == TRANSPORT_VPN) {
                    param.setResult(Boolean.FALSE);
                }
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.net.NetworkCapabilities", null,
                    "hasTransport", int.class, hook);
        } catch (Throwable ignore) {
        }
    }

    // ------------------------------------------------------------------
    // 2. 虚拟网卡列表过滤
    // ------------------------------------------------------------------

    private static void hookNetworkInterfaces() {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof Enumeration)) return;
                try {
                    List<NetworkInterface> keep = new ArrayList<NetworkInterface>();
                    boolean changed = false;
                    Enumeration<?> en = (Enumeration<?>) r;
                    while (en.hasMoreElements()) {
                        Object o = en.nextElement();
                        if (!(o instanceof NetworkInterface)) continue;
                        NetworkInterface ni = (NetworkInterface) o;
                        if (isVirtual(ni.getName())) {
                            changed = true;
                            continue;
                        }
                        keep.add(ni);
                    }
                    if (changed) param.setResult(Collections.enumeration(keep));
                } catch (Throwable ignore) {
                }
            }
        };
        try {
            XposedHelpers.findAndHookMethod("java.net.NetworkInterface", null,
                    "getNetworkInterfaces", hook);
        } catch (Throwable ignore) {
        }
        try {
            XposedHelpers.findAndHookMethod("java.net.NetworkInterface", null,
                    "getByName", String.class, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            if (param.args == null || param.args.length < 1) return;
                            Object a0 = param.args[0];
                            if (a0 instanceof String && isVirtual((String) a0)) {
                                param.setResult(null);
                            }
                        }
                    });
        } catch (Throwable ignore) {
        }
    }

    private static boolean isVirtual(String name) {
        if (name == null) return false;
        String n = name.toLowerCase(Locale.ROOT);
        for (String p : VIRT_PREFIX) {
            if (n.equals(p) || n.startsWith(p)) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // 3. 代理属性
    // ------------------------------------------------------------------

    private static void hookProxyProps() {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                if (param.args == null || param.args.length < 1) return;
                Object a0 = param.args[0];
                if (!(a0 instanceof String)) return;
                if (!isProxyKey((String) a0)) return;
                Object r = param.getResult();
                if (r == null) return;
                param.setResult(null);
            }
        };
        try {
            XposedHelpers.findAndHookMethod("java.lang.System", null,
                    "getProperty", String.class, hook);
        } catch (Throwable ignore) {
        }
    }

    /** 链路代理对象与环境变量：getHttpProxy 返回 null，代理类环境变量返回 null */
    /** 链路代理对象：getHttpProxy 返回 null */
    private static void hookLinkProxy() {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (param.getResult() == null) return;
                param.setResult(null);
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.net.LinkProperties", null,
                    "getHttpProxy", hook);
        } catch (Throwable ignore) {
        }
    }

    /** 代理类环境变量：http_proxy / https_proxy / socks_proxy 一律读不到 */
    private static void hookProxyEnv() {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object a0 = (param.args != null && param.args.length > 0) ? param.args[0] : null;
                if (!(a0 instanceof String)) return;
                if (!isProxySetting((String) a0)) return;
                if (param.getResult() == null) return;
                param.setResult(null);
            }
        };
        try {
            XposedHelpers.findAndHookMethod("java.lang.System", null,
                    "getenv", String.class, hook);
        } catch (Throwable ignore) {
        }
    }

    private static boolean isProxyKey(String key) {
        for (String k : PROXY_KEYS) {
            if (k.equals(key)) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // 4. 系统设置里的代理条目
    // ------------------------------------------------------------------

    private static void hookGlobalProxy() {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                if (param.args == null || param.args.length < 2) return;
                Object a1 = param.args[1];
                if (!(a1 instanceof String)) return;
                if (!isProxySetting((String) a1)) return;
                Object r = param.getResult();
                if (r == null) return;
                if (r instanceof Integer) {
                    param.setResult(Integer.valueOf(0));
                } else {
                    param.setResult(null);
                }
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.provider.Settings$Global", null,
                    "getString", android.content.ContentResolver.class, String.class, hook);
        } catch (Throwable ignore) {
        }
        try {
            XposedHelpers.findAndHookMethod("android.provider.Settings$Global", null,
                    "getInt", android.content.ContentResolver.class, String.class, hook);
        } catch (Throwable ignore) {
        }
    }

    private static boolean isProxySetting(String key) {
        for (String k : PROXY_SETTINGS) {
            if (k.equalsIgnoreCase(key)) return true;
        }
        return false;
    }
}
