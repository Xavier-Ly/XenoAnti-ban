package qwq.love.dfy.xy;

/**
 * 字符串拼接工具
 *
 * 说明：模块源码需在低版本 Java 语言级别下编译（与 android.jar 引导类库兼容），
 * 因此统一用 StringBuilder 拼接，不使用「+」运算符做字符串连接。
 */
public final class S {

    private S() {}

    public static String of(Object... parts) {
        if (parts == null || parts.length == 0) return "";
        StringBuilder sb = new StringBuilder(64);
        for (int i = 0; i < parts.length; i++) {
            sb.append(parts[i]);
        }
        return sb.toString();
    }
}
