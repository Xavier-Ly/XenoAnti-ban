package qwq.love.dfy.xy;

import android.content.ContentResolver;
import android.content.Context;
import android.os.Build;

import java.io.File;
import java.lang.reflect.Method;
import java.security.MessageDigest;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedHelpers;

/**
 * 异客防封 —— 多开 / 一机多号 设备指纹隔离
 *
 * 目标：同一台手机上跑多个实例（应用分身、工作资料、虚拟空间、双开容器），
 *      每个实例对外报出「一套不同、但内部自洽」的硬件标识，
 *      避免服务端把多个账号判定成同一台设备。
 *
 * 隔离种子取自实例自己的数据目录路径：
 *   /data/user/0/com.netease.sky
 *   /data/user/999/com.netease.sky
 *   /data/data/com.lbe.parallel/virtual/data/user/0/com.netease.sky
 * 同一实例每次拿到的是同一套值（不会因为重启而变，避免被判定为异常），
 * 不同实例之间互不相同。
 *
 * 五条自我约束：
 *   · 只改「查询结果」，不改系统行为，不拦截任何调用
 *   · 原值为 null / 空 / 抛异常时一律不动 —— 系统本来就不给的值，改了才可疑
 *   · 生成的号全部符合格式规范（IMEI / ICCID 过 Luhn 校验，IMSI 合法 MCC+MNC 前缀）
 *   · 只挂在设备标识类 API 上，不碰文件、不碰网络、不碰游戏业务
 *   · 任何一步失败都只跳过自己，不影响其余模块和游戏启动
 */
public final class FingerprintIsolation {

    private FingerprintIsolation() {}

    private static volatile String SEED;
    /** 指纹槽位缓存，-1 表示还没读 */
    private static volatile int SLOT = -1;

    private static final ThreadLocal<Boolean> BUSY = new ThreadLocal<Boolean>();

    private static final String K_ANDROID_ID = "android_id";

    public static void install(ClassLoader cl) {
        // 先把槽位读出来，保证 seed 第一次算出来就是最终值
        try { slot(); } catch (Throwable ignore) {}
        try { hookAppReady(); } catch (Throwable ignore) {}
        try { seed(); } catch (Throwable ignore) {}
        try { hookTelephony(); } catch (Throwable ignore) {}
        try { hookAndroidId(); } catch (Throwable ignore) {}
        try { hookSerial(); } catch (Throwable ignore) {}
        try { hookMac(); } catch (Throwable ignore) {}
        try { hookMediaDrm(); } catch (Throwable ignore) {}
        try { hookBluetooth(); } catch (Throwable ignore) {}
        try { hookWifiExtra(); } catch (Throwable ignore) {}
    }

    // ------------------------------------------------------------------
    // 种子：实例数据目录 + 机器原始特征
    // ------------------------------------------------------------------

    /**
     * Application一就绪就立刻把种子定下来。
     *
     * 原因：handleLoadPackage 阶段拿不到 Context，此时算出来的种子只有 Build 字段，
     * 所有实例会算出同一个值；等 Application.attach 之后有了实例数据目录才是真种子。
     * 在这里补一次，保证「第一次查询标识」时种子已经是按实例区分的那一套，
     * 避免同一个进程里前后报出两套不同的号。
     */
    private static void hookAppReady() {
        XC_MethodHook h = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                try {
                    if (SEED == null) seed();
                } catch (Throwable ignore) {
                }
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.app.Application", null,
                    "attach", Context.class, h);
        } catch (Throwable ignore) {
        }
        try {
            XposedHelpers.findAndHookMethod("android.app.Application", null,
                    "onCreate", h);
        } catch (Throwable ignore) {
        }
    }

    private static String seed() {
        String s = SEED;
        if (s != null) return s;
        StringBuilder sb = new StringBuilder(160);
        // 槽位：一号一指纹（在模块 App 里选 1~5），切号换槽位整套标识跟着换
        try { sb.append('|').append(slot()); } catch (Throwable ignore) {}
        // 实例 uid：应用分身 / 工作资料 / 双开容器下每个实例 uid 不同
        try { sb.append('|').append(android.os.Process.myUid()); } catch (Throwable ignore) {}
        // 机型字段：不依赖 Context，任何时刻算出来都一样，进程内不会前后跳变
        try { sb.append('|').append(Build.FINGERPRINT); } catch (Throwable ignore) {}
        try { sb.append('|').append(Build.MODEL); } catch (Throwable ignore) {}
        try { sb.append('|').append(Build.BRAND); } catch (Throwable ignore) {}
        try { sb.append('|').append(Build.MANUFACTURER); } catch (Throwable ignore) {}
        try { sb.append('|').append(Build.DEVICE); } catch (Throwable ignore) {}
        s = sha256(sb.toString());
        SEED = s;
        return s;
    }

    /** 指纹槽位：从模块 App 的 SharedPreferences 读，1~5；读不到按 0 处理 */
    private static int slot() {
        int v = SLOT;
        if (v >= 0) return v;
        // 递归保护：读 prefs 本身可能又触发被 hook 的方法，这时先按 0 用，不写缓存
        if (Boolean.TRUE.equals(BUSY.get())) return 0;
        int out = 0;
        BUSY.set(Boolean.TRUE);
        try {
            XSharedPreferences p = new XSharedPreferences("com.yikefangfeng.xeno", "dfy_prefs");
            int raw = p.getInt("slot", 1);
            if (raw >= 1 && raw <= 5) out = raw;
        } catch (Throwable ignore) {
        } finally {
            BUSY.set(Boolean.FALSE);
        }
        SLOT = out;
        return out;
    }

    private static Context app() {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Method m = at.getMethod("currentApplication");
            Object o = m.invoke(null);
            if (o instanceof Context) return (Context) o;
        } catch (Throwable ignore) {}
        return null;
    }

    private static String sha256(String in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(in.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Throwable t) {
            return S.of(Integer.toHexString(in.hashCode()), Integer.toHexString(in.length()));
        }
    }

    /** 从种子派生 len 位十进制数字，salt 不同则值不同 */
    private static String digits(int salt, int len) {
        StringBuilder sb = new StringBuilder(len);
        String base = S.of(seed(), "#", salt);
        int round = 0;
        while (sb.length() < len && round < 16) {
            String h = sha256(S.of(base, "$", round));
            for (int i = 0; i < h.length() && sb.length() < len; i++) {
                int v = Character.digit(h.charAt(i), 16);
                if (v < 0) continue;
                sb.append((char) ('0' + (v % 10)));
            }
            round++;
        }
        while (sb.length() < len) sb.append('7');
        return sb.substring(0, len);
    }

    /** 从种子派生 len 位十六进制小写 */
    private static String hex(int salt, int len) {
        StringBuilder sb = new StringBuilder(len);
        String base = S.of(seed(), "&", salt);
        int round = 0;
        while (sb.length() < len && round < 16) {
            String h = sha256(S.of(base, "$", round));
            sb.append(h);
            round++;
        }
        return sb.substring(0, len);
    }

    /** 追加 Luhn 校验位 */
    private static String withLuhn(String body) {
        int sum = 0;
        boolean dbl = true;
        for (int i = body.length() - 1; i >= 0; i--) {
            int d = body.charAt(i) - '0';
            if (d < 0 || d > 9) return body;
            if (dbl) {
                d *= 2;
                if (d > 9) d -= 9;
            }
            dbl = !dbl;
            sum += d;
        }
        return S.of(body, (10 - (sum % 10)) % 10);
    }

    /** IMEI：TAC 按机型厂商挑 + 6 位序列 + 1 位校验 = 15 位 */
    static String imei() {
        String body = S.of(tac(), digits(11, 4), digits(12, 6));
        return withLuhn(body.length() == 14 ? body : body.substring(0, 14));
    }

    /** IMSI：中国运营商 MCC+MNC + 10 位 = 15 位 */
    static String imsi() {
        return S.of(imsiPrefix(), digits(21, 10));
    }

    /** ICCID：运营商段 + 13 位 + 校验 = 20 位 */
    static String iccid() {
        String body = S.of(iccidPrefix(), digits(31, 13));
        return withLuhn(body.length() == 19 ? body : body.substring(0, 19));
    }

    private static final String[] IMSI_PREFIX = {
            "46000", "46001", "46002", "46003", "46007", "46011", "46015"
    };

    private static final String[] ICCID_PREFIX = {
            "898600", "898601", "898603", "898607", "898611"
    };

    static String imsiPrefix() {
        return IMSI_PREFIX[idxOf(IMSI_PREFIX.length, 21)];
    }

    static String iccidPrefix() {
        return ICCID_PREFIX[idxOf(ICCID_PREFIX.length, 31)];
    }

    /** 按种子在 range 内取稳定下标 */
    private static int idxOf(int range, int salt) {
        if (range <= 1) return 0;
        int v = 0;
        try {
            v = Integer.parseInt(digits(salt, 4));
        } catch (Throwable ignore) {
        }
        return Math.abs(v) % range;
    }
    /** 按机型厂商挑一个可信的 TAC 前缀，避免所有用户挤在同一段 */
    private static String tac() {
        String m = "";
        try {
            m = S.of(Build.MANUFACTURER, Build.BRAND).toLowerCase(java.util.Locale.ROOT);
        } catch (Throwable ignore) {
        }
        String[] list;
        if (m.indexOf("xiaomi") >= 0 || m.indexOf("redmi") >= 0 || m.indexOf("poco") >= 0) {
            list = new String[]{"8601", "8612", "8625", "8639"};
        } else if (m.indexOf("huawei") >= 0 || m.indexOf("honor") >= 0) {
            list = new String[]{"8617", "8628", "8633", "8641"};
        } else if (m.indexOf("samsung") >= 0) {
            list = new String[]{"3522", "3546", "3568", "3579"};
        } else if (m.indexOf("oppo") >= 0 || m.indexOf("oneplus") >= 0 || m.indexOf("realme") >= 0) {
            list = new String[]{"8650", "8657", "8662"};
        } else if (m.indexOf("vivo") >= 0 || m.indexOf("iqoo") >= 0) {
            list = new String[]{"8613", "8621", "8648"};
        } else {
            list = new String[]{"3516", "3551", "8619", "8692"};
        }
        return list[idxOf(list.length, 51)];
    }

    static String operatorName() {
        String p = imsiPrefix();
        if ("46001".equals(p) || "46006".equals(p)) return "CHINA UNICOM";
        if ("46003".equals(p) || "46011".equals(p)) return "CHINA TELECOM";
        return "CHINA MOBILE";
    }

    /** android_id：16 位十六进制 */
    static String androidId() {
        return hex(41, 16);
    }

    /** 序列号：真机常见 12 位大写字母数字 */
    static String serial() {
        String h = hex(51, 12).toUpperCase(java.util.Locale.ROOT);
        return h;
    }

    /** MAC：厂商 OUI + 3 字节派生值，不用 02:00:00:00:00:00 这种被屏蔽的特征 */
    static String mac() {
        String h = hex(61, 6).toUpperCase(java.util.Locale.ROOT);
        return S.of("3C:5A:B4:", h.substring(0, 2), ":", h.substring(2, 4), ":", h.substring(4, 6));
    }

    /** 蓝牙地址：与 WiFi MAC 同 OUI 相邻地址，真机上两者本来就差 1~2 */
    static String btMac() {
        String h = hex(61, 6).toUpperCase(java.util.Locale.ROOT);
        int last = Integer.parseInt(h.substring(4, 6), 16) + 1;
        if (last > 0xFF) last = 0;
        String tail = Integer.toHexString(last).toUpperCase(java.util.Locale.ROOT);
        if (tail.length() < 2) tail = S.of("0", tail);
        return S.of("3C:5A:B4:", h.substring(0, 2), ":", h.substring(2, 4), ":", tail);
    }

    /** 热点 BSSID：按槽位派生，避免同 WiFi 下多个账号共用同一个 BSSID */
    static String bssid() {
        String h = hex(63, 6).toUpperCase(java.util.Locale.ROOT);
        return S.of("3C:5A:B4:", h.substring(0, 2), ":", h.substring(2, 4), ":", h.substring(4, 6));
    }

    /** 主机名（net.hostname 那个） */
    static String hostname() {
        return S.of("Android_", hex(71, 8));
    }

    // ------------------------------------------------------------------
    // 1. 电话 / SIM 标识
    // ------------------------------------------------------------------

    /** 固定值型字符串 hook */
    private static void bindConst(String cls, String method, final String value) {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof String)) return;
                if (((String) r).length() == 0) return;
                param.setResult(value);
            }
        };
        try {
            XposedHelpers.findAndHookMethod(cls, null, method, hook);
        } catch (Throwable ignore) {
        }
    }

    /** WiFi 热点 BSSID：按槽位派生 */
    private static void hookWifiExtra() {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof String)) return;
                if (((String) r).length() == 0) return;
                param.setResult(bssid());
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.net.wifi.WifiInfo", null, "getBSSID", hook);
        } catch (Throwable ignore) {
        }
    }
    private static void hookTelephony() {
        String cls = "android.telephony.TelephonyManager";
        bindString(cls, "getDeviceId", 81, 0);
        bindString(cls, "getDeviceId", 81, 1);
        bindString(cls, "getImei", 81, 0);
        bindString(cls, "getImei", 81, 1);
        bindString(cls, "getMeid", 82, 0);
        bindString(cls, "getMeid", 82, 1);
        bindString(cls, "getSubscriberId", 83, 0);
        bindString(cls, "getSubscriberId", 83, 1);
        bindString(cls, "getSimSerialNumber", 84, 0);
        bindString(cls, "getSimSerialNumber", 84, 1);
        bindString(cls, "getIccId", 84, 0);
        // 运营商字段：必须与伪造的 IMSI 前 5 位一致，否则交叉比对就穿帮
        bindConst(cls, "getNetworkOperator", imsiPrefix());
        bindConst(cls, "getSimOperator", imsiPrefix());
        bindConst(cls, "getNetworkOperatorName", operatorName());
        bindConst(cls, "getSimOperatorName", operatorName());
    }

    /**
     * @param intArgs 0 表示无参重载，1 表示带一个 int（subscriptionId）的重载
     */
    private static void bindString(String cls, String method, final int kind, int intArgs) {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof String)) return;
                String cur = (String) r;
                if (cur.length() == 0) return;
                BUSY.set(Boolean.TRUE);
                try {
                    param.setResult(valueOf(kind));
                } finally {
                    BUSY.set(Boolean.FALSE);
                }
            }
        };
        try {
            if (intArgs == 0) {
                XposedHelpers.findAndHookMethod(cls, null, method, hook);
            } else {
                XposedHelpers.findAndHookMethod(cls, null, method, int.class, hook);
            }
        } catch (Throwable ignore) {
        }
    }

    private static String valueOf(int kind) {
        switch (kind) {
            case 81: return imei();
            case 82: return imei();
            case 83: return imsi();
            case 84: return iccid();
            default: return "";
        }
    }

    // ------------------------------------------------------------------
    // 2. android_id（Settings.Secure.getString）
    //    只对这一个 key 生效，其它设置项原样返回，不影响游戏读系统设置
    // ------------------------------------------------------------------

    private static void hookAndroidId() {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                if (param.args == null || param.args.length < 2) return;
                Object k = param.args[1];
                if (!(k instanceof String) || !K_ANDROID_ID.equals(k)) return;
                Object r = param.getResult();
                if (r == null) return;
                if (!(r instanceof String) || ((String) r).length() == 0) return;
                param.setResult(androidId());
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.provider.Settings$Secure", null,
                    "getString", ContentResolver.class, String.class, hook);
        } catch (Throwable ignore) {
        }
    }

    // ------------------------------------------------------------------
    // 3. 序列号
    // ------------------------------------------------------------------

    private static void hookSerial() {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof String)) return;
                if (((String) r).length() == 0) return;
                param.setResult(serial());
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.os.Build", null, "getSerial", hook);
        } catch (Throwable ignore) {
        }
        try {
            Object cur = XposedHelpers.getStaticObjectField(Build.class, "SERIAL");
            if (cur instanceof String) {
                XposedHelpers.setStaticObjectField(Build.class, "SERIAL", serial());
            }
        } catch (Throwable ignore) {
        }
    }

    /**
     * MediaDrm（Widevine）设备唯一 ID
     *
     * 服务端设备指纹里权重极高的一条：同机型不同实例必然相同，
     * 一旦被拿去关联，多开等于白开。这里按实例派生 16 字节，等长替换。
     */
    private static void hookMediaDrm() {
        XC_MethodHook h = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                if (param.args == null || param.args.length < 1) return;
                Object k = param.args[0];
                if (!(k instanceof String) || !"deviceUniqueId".equals(k)) return;
                Object r = param.getResult();
                if (!(r instanceof byte[])) return;
                BUSY.set(Boolean.TRUE);
                try {
                    param.setResult(mediaDrmId());
                } catch (Throwable ignore) {
                } finally {
                    BUSY.set(Boolean.FALSE);
                }
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.media.MediaDrm", null,
                    "getPropertyByteArray", String.class, h);
        } catch (Throwable ignore) {
        }
    }

    /** 16 字节派生值（与原值等长） */
    static byte[] mediaDrmId() {
        String h = hex(91, 32);
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            try {
                out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
            } catch (Throwable ignore) {
                out[i] = 0;
            }
        }
        return out;
    }

    /**
     * 蓝牙 MAC：Android 6 以上通常返回 02:00:00:00:00:00，取到真实值的老系统
     * 直接换成跟 WiFi MAC 同源的派生值。
     */
    private static void hookBluetooth() {
        XC_MethodHook h = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof String)) return;
                if (((String) r).length() == 0) return;
                param.setResult(btMac());
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.bluetooth.BluetoothAdapter", null,
                    "getAddress", h);
        } catch (Throwable ignore) {
        }
    }

    // ------------------------------------------------------------------
    // 4. WiFi MAC
    // ------------------------------------------------------------------

    private static void hookMac() {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof String)) return;
                if (((String) r).length() == 0) return;
                param.setResult(mac());
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.net.wifi.WifiInfo", null,
                    "getMacAddress", hook);
        } catch (Throwable ignore) {
        }
        // Android 6+ 更常用 LinkProperties.getMacAddress()，返回 MacAddress 对象
        XC_MethodHook lp = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (r == null) return;
                BUSY.set(Boolean.TRUE);
                try {
                    Class<?> mc = Class.forName("android.net.MacAddress");
                    Method from = mc.getMethod("fromString", String.class);
                    Object v = from.invoke(null, mac());
                    if (v != null) param.setResult(v);
                } catch (Throwable ignore) {
                } finally {
                    BUSY.set(Boolean.FALSE);
                }
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.net.LinkProperties", null,
                    "getMacAddress", lp);
        } catch (Throwable ignore) {
        }
    }
}
