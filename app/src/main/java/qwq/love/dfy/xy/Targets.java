package qwq.love.dfy.xy;

/**
 * 目标包名（光·遇各渠道）
 *
 * 渠道包是同一个游戏的不同发行包，每个包各自有独立的数据目录，
 * 所以作用域、数据目录豁免都必须按这张表走，不能只认官方包。
 */
public final class Targets {

    private Targets() {}

    public static final String[] PKGS = {
            "com.netease.sky",           // 官服
            "com.netease.sky.bilibili",  // B 站服
            "com.netease.sky.huawei",    // 华为服
            "com.netease.sky.vivo",      // vivo 服
            "com.netease.sky.aligames",  // 九游服
            "com.netease.sky.m4399",     // 4399 服
            "com.tencent.tmgp.eyou.eygy" // 应用宝服
    };

    /** 是否目标包（精确匹配） */
    public static boolean isTarget(String pkg) {
        if (pkg == null) return false;
        for (String p : PKGS) {
            if (p.equals(pkg)) return true;
        }
        return false;
    }

    /** 官方包名，用于界面展示与日志 */
    public static final String PRIMARY = "com.netease.sky";
}
