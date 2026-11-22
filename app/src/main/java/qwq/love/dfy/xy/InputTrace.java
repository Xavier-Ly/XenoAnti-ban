package qwq.love.dfy.xy;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;

/**
 * 异客防封 —— 脚本挂机 / 自动化输入痕迹
 *
 * 作用：把「这段操作是脚本灌进来的」这类本地可探测特征抹平，让输入在游戏看来
 *      就是一块普通触摸屏按出来的。
 *
 * 三个落点（全部是只读查询，不拦任何调用）：
 *   1. 事件标记     MotionEvent 上的注入标记位（FLAG_TAINTED）清掉
 *   2. 输入设备     MotionEvent 报出的 deviceId 归一成触摸屏的 0（-1 是典型注入特征）
 *   3. 无障碍服务   自动点击器 / 投屏 / 自动化工具的无障碍服务从查询结果里消失
 * 外加 AntiDetect 侧的 /proc/bus/input/devices 清洗（uinput 虚拟输入设备不在列表里）
 *
 * 三条自我约束：
 *   · 只在「值确实是异常特征」时才改，正常触摸事件原样透传
 *   · 不改坐标、不改时间、不改压力、不改指针数量 —— 手势识别不受影响
 *   · 无障碍列表只按精确黑名单剔除，系统自带和游戏自己的服务一律保留
 */
public final class InputTrace {

    private InputTrace() {}

    private static volatile int TOUCH_ID = -1;

    /** 真实触摸屏的设备号：扫一遍输入设备，取第一个支持触摸屏的 id
     *  （原来把 -1 改成 0 反而更可疑，0 本身就是虚拟设备号） */
    private static int touchDeviceId() {
        int cached = TOUCH_ID;
        if (cached >= 0) return cached;
        int found = -1;
        try {
            Class<?> c = Class.forName("android.view.InputDevice");
            int[] ids = (int[]) c.getMethod("getDeviceIds").invoke(null);
            if (ids != null) {
                for (int i = 0; i < ids.length; i++) {
                    Object dev = c.getMethod("getDevice", int.class)
                            .invoke(null, Integer.valueOf(ids[i]));
                    if (dev == null) continue;
                    Object src = c.getMethod("getSources").invoke(dev);
                    if (!(src instanceof Integer)) continue;
                    if ((((Integer) src).intValue() & 0x00000002) != 0) {
                        found = ids[i];
                        break;
                    }
                }
            }
        } catch (Throwable ignore) {
        }
        if (found < 0) found = 1;
        TOUCH_ID = found;
        return found;
    }
    private static final ThreadLocal<Boolean> BUSY = new ThreadLocal<Boolean>();

    /** MotionEvent.FLAG_TAINTED —— 标记该事件由非真实输入源注入 */
    private static final int FLAG_TAINTED = 0x80000000;

    /** 自动点击 / 投屏 / 自动化工具的包名或类名特征（小写、按包含匹配） */
    private static final String[] AUTO_MARKS = {
            "autoclick", "auto.click", "auto_click", "clicker", "clickservice",
            "autotap", "auto.tap", "toucher", "minitouch", "scrcpy", "anlink",
            "autotouch", "automation.service", "accessibility.automation"
    };

    public static void install(ClassLoader cl) {
        try { hookMotionFlags(); } catch (Throwable ignore) {}
        try { hookDeviceId(); } catch (Throwable ignore) {}
        try { hookAccessibility(); } catch (Throwable ignore) {}
    }

    // ------------------------------------------------------------------
    // 1. 清掉事件上的注入标记位
    // ------------------------------------------------------------------

    private static void hookMotionFlags() {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof Integer)) return;
                int f = ((Integer) r).intValue();
                if ((f & FLAG_TAINTED) == 0) return;
                param.setResult(Integer.valueOf(f & ~FLAG_TAINTED));
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.view.MotionEvent", null,
                    "getFlags", hook);
        } catch (Throwable ignore) {
        }
        try {
            XposedHelpers.findAndHookMethod("android.view.InputEvent", null,
                    "getFlags", hook);
        } catch (Throwable ignore) {
        }
    }

    // ------------------------------------------------------------------
    // 2. deviceId 归一：-1（未知 / 虚拟设备）一律报 0（真实触摸屏）
    // ------------------------------------------------------------------

    private static void hookDeviceId() {
        XC_MethodHook hook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof Integer)) return;
                int id = ((Integer) r).intValue();
                if (id < 0) param.setResult(Integer.valueOf(touchDeviceId()));
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.view.MotionEvent", null,
                    "getDeviceId", hook);
        } catch (Throwable ignore) {
        }
    }

    // ------------------------------------------------------------------
    // 3. 无障碍服务列表：自动点击 / 投屏 / 自动化工具隐身
    // ------------------------------------------------------------------

    private static void hookAccessibility() {
        XC_MethodHook listHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (Boolean.TRUE.equals(BUSY.get())) return;
                Object r = param.getResult();
                if (!(r instanceof List)) return;
                List<?> src = (List<?>) r;
                if (src.isEmpty()) return;
                List<Object> out = new ArrayList<Object>(src.size());
                boolean changed = false;
                for (Object o : src) {
                    if (isAutoService(o)) {
                        changed = true;
                        continue;
                    }
                    out.add(o);
                }
                if (changed) param.setResult(out);
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.view.accessibility.AccessibilityManager",
                    null, "getEnabledAccessibilityServiceList", int.class, listHook);
        } catch (Throwable ignore) {
        }
        try {
            XposedHelpers.findAndHookMethod("android.view.accessibility.AccessibilityManager",
                    null, "getInstalledAccessibilityServiceList", listHook);
        } catch (Throwable ignore) {
        }
    }

    private static boolean isAutoService(Object o) {
        if (o == null) return false;
        String pkg = null;
        String cls = null;
        try {
            Method gr = o.getClass().getMethod("getResolveInfo");
            Object ri = gr.invoke(o);
            if (ri != null) {
                Field sf = ri.getClass().getField("serviceInfo");
                Object si = sf.get(ri);
                if (si != null) {
                    pkg = str(si, "packageName");
                    cls = str(si, "name");
                }
            }
        } catch (Throwable ignore) {
        }
        return hit(pkg) || hit(cls);
    }

    private static String str(Object o, String field) {
        try {
            Field f = o.getClass().getField(field);
            Object v = f.get(o);
            return (v instanceof String) ? (String) v : null;
        } catch (Throwable ignore) {
            return null;
        }
    }

    private static boolean hit(String s) {
        if (s == null || s.length() == 0) return false;
        String low = s.toLowerCase(Locale.ROOT);
        for (String m : AUTO_MARKS) {
            if (low.indexOf(m) >= 0) return true;
        }
        return false;
    }
}
