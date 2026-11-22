package com.yikefangfeng.xeno

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread
import org.json.JSONObject
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// 宋体：Compose 的 Serif 族在 Android 上解析为 Noto Serif / Noto Serif CJK，
// 中文即宋体字形。界面所有文字统一走这个字族，不混用无衬线。
private val SongTi = FontFamily.Serif

private val Paper = Color(0xFFF5F1E8)
private val PaperDeep = Color(0xFFEDE6D8)
private val Card = Color(0xFFFFFDF7)
private val Ink = Color(0xFF1E1B16)
private val InkSoft = Color(0xFF6C6457)
private val Bronze = Color(0xFF9A6B33)
private val Line = Color(0xFFDDD3BF)
private val Jade = Color(0xFF3F6B58)

private val AppColors = lightColorScheme(
    primary = Bronze,
    onPrimary = Color.White,
    background = Paper,
    onBackground = Ink,
    surface = Card,
    onSurface = Ink,
)

// Material 默认排版也换成宋体，避免任何组件回落到无衬线
private val SongTypography = Typography().let { t ->
    t.copy(
        displayLarge = t.displayLarge.copy(fontFamily = SongTi),
        displayMedium = t.displayMedium.copy(fontFamily = SongTi),
        displaySmall = t.displaySmall.copy(fontFamily = SongTi),
        headlineLarge = t.headlineLarge.copy(fontFamily = SongTi),
        headlineMedium = t.headlineMedium.copy(fontFamily = SongTi),
        headlineSmall = t.headlineSmall.copy(fontFamily = SongTi),
        titleLarge = t.titleLarge.copy(fontFamily = SongTi),
        titleMedium = t.titleMedium.copy(fontFamily = SongTi),
        titleSmall = t.titleSmall.copy(fontFamily = SongTi),
        bodyLarge = t.bodyLarge.copy(fontFamily = SongTi),
        bodyMedium = t.bodyMedium.copy(fontFamily = SongTi),
        bodySmall = t.bodySmall.copy(fontFamily = SongTi),
        labelLarge = t.labelLarge.copy(fontFamily = SongTi),
        labelMedium = t.labelMedium.copy(fontFamily = SongTi),
        labelSmall = t.labelSmall.copy(fontFamily = SongTi),
    )
}

/** 界面统一文本组件：字号、字重、行距、颜色全部以宋体呈现 */
@Composable
private fun SongText(
    text: String,
    modifier: Modifier = Modifier,
    size: TextUnit = 14.sp,
    weight: FontWeight = FontWeight.Normal,
    color: Color = Ink,
    lineHeight: TextUnit = size * 1.75f,
) {
    Text(
        text = text,
        modifier = modifier,
        color = color,
        fontSize = size,
        fontWeight = weight,
        fontFamily = SongTi,
        lineHeight = lineHeight,
    )
}

/** 章节标题：左侧一竖线，右侧宋体小标题 */
@Composable
private fun SectionTitle(text: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 22.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.width(3.dp).height(15.dp).background(Bronze, RoundedCornerShape(2.dp)))
        Spacer(Modifier.width(9.dp))
        SongText(text, size = 15.sp, weight = FontWeight.SemiBold, color = Ink, lineHeight = 20.sp)
    }
}

/** 卡片容器：纸色底、细描边 */
@Composable
private fun PaperCard(content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(Card, RoundedCornerShape(14.dp))
            .border(1.dp, Line, RoundedCornerShape(14.dp))
            .padding(horizontal = 16.dp, vertical = 14.dp),
        content = content,
    )
}

@Composable
private fun StatusRow(label: String, value: String, accent: Boolean = false) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        SongText(label, size = 13.sp, color = InkSoft, lineHeight = 18.sp)
        Spacer(Modifier.width(12.dp))
        Box(Modifier.weight(1f).height(1.dp).background(Line.copy(alpha = 0.7f)))
        Spacer(Modifier.width(12.dp))
        SongText(
            value,
            size = 13.sp,
            weight = FontWeight.Medium,
            color = if (accent) Bronze else Ink,
            lineHeight = 18.sp,
        )
    }
}

@Composable
private fun FeatureCard(index: String, title: String, desc: String) {
    PaperCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(24.dp)
                    .background(PaperDeep, RoundedCornerShape(7.dp))
                    .border(1.dp, Line, RoundedCornerShape(7.dp)),
                contentAlignment = Alignment.Center,
            ) {
                SongText(index, size = 12.sp, color = Bronze, weight = FontWeight.SemiBold, lineHeight = 14.sp)
            }
            Spacer(Modifier.width(10.dp))
            SongText(title, size = 15.sp, weight = FontWeight.SemiBold, color = Ink, lineHeight = 20.sp)
        }
        Spacer(Modifier.height(8.dp))
        SongText(desc, size = 13.sp, color = InkSoft, lineHeight = 22.sp)
    }
}

@Composable
private fun StepRow(step: String, text: String) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        SongText(step, size = 13.sp, color = Bronze, weight = FontWeight.SemiBold, lineHeight = 22.sp)
        Spacer(Modifier.width(8.dp))
        SongText(text, size = 13.sp, color = Ink, lineHeight = 22.sp)
    }
}

@Composable
private fun AppScreen() {
    val ctx = LocalContext.current
    val prefs = remember { ctx.getSharedPreferences("dfy_prefs", Context.MODE_PRIVATE) }
    var slot by remember { mutableStateOf(prefs.getInt("slot", 1)) }
    var checking by remember { mutableStateOf(false) }
    var update by remember { mutableStateOf<UpdateInfo?>(null) }
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(listOf(Paper, PaperDeep))),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 28.dp),
        ) {
            // 标题区
            SongText("异客防封", size = 30.sp, weight = FontWeight.Bold, color = Ink, lineHeight = 40.sp)
            Spacer(Modifier.height(6.dp))
            SongText("光·遇 本地环境隔离模块", size = 13.sp, color = InkSoft, lineHeight = 20.sp)
            Spacer(Modifier.height(14.dp))
            Box(Modifier.fillMaxWidth().height(1.dp).background(Line))

            SectionTitle("模块状态")
            PaperCard {
                StatusRow("模块版本", localVersionName(ctx))
                StatusRow("目标应用", "光·遇")
                StatusRow("作用域包名", "7 个渠道", accent = true)
                listOf(
                    "com.netease.sky",
                    "com.netease.sky.bilibili",
                    "com.netease.sky.huawei",
                    "com.netease.sky.vivo",
                    "com.netease.sky.aligames",
                    "com.netease.sky.m4399",
                    "com.tencent.tmgp.eyou.eygy",
                ).forEach { p ->
                    SongText(p, size = 11.sp, color = InkSoft, lineHeight = 17.sp)
                }
                StatusRow("运行框架", "LSPosed / Xposed")
                StatusRow("注入时机", "进程加载时")
                Spacer(Modifier.height(6.dp))
                Box(Modifier.fillMaxWidth().height(1.dp).background(Line))
                Spacer(Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    SongText("版本检测", size = 13.sp, color = InkSoft)
                    Spacer(Modifier.weight(1f))
                    Box(
                        modifier = Modifier
                            .background(Paper, RoundedCornerShape(3.dp))
                            .border(1.dp, Bronze, RoundedCornerShape(3.dp))
                            .clickable(enabled = !checking) {
                                checking = true
                                checkUpdate(
                                    ctx = ctx,
                                    onDone = { info ->
                                        Handler(Looper.getMainLooper()).post {
                                            checking = false
                                            if (info == null) {
                                                Toast.makeText(ctx, "现在是最新版本", Toast.LENGTH_SHORT).show()
                                            } else {
                                                update = info
                                            }
                                        }
                                    },
                                    onError = { msg ->
                                        Handler(Looper.getMainLooper()).post {
                                            checking = false
                                            Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show()
                                        }
                                    },
                                )
                            }
                            .padding(horizontal = 12.dp, vertical = 6.dp),
                    ) {
                        SongText(
                            text = if (checking) "检测中…" else "检测更新",
                            size = 12.sp,
                            weight = FontWeight.SemiBold,
                            color = Bronze,
                        )
                    }
                }
                StatusRow("注入时机", "进程加载时")
            }

            SectionTitle("指纹槽位")
            PaperCard {
                SongText(
                    "同机多账号时，每个号选一个不同槽位：整套设备标识（IMEI / IMSI / ICCID / android_id / 序列号 / MAC / 蓝牙 / MediaDrm）都跟着换；同一槽位重启后保持不变。",
                    size = 13.sp,
                    color = InkSoft,
                )
                Spacer(Modifier.height(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    for (i in 1..5) {
                        val on = i == slot
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .height(40.dp)
                                .background(if (on) Bronze else Paper, RoundedCornerShape(3.dp))
                                .border(1.dp, if (on) Bronze else Line, RoundedCornerShape(3.dp))
                                .clickable {
                                    slot = i
                                    prefs.edit().putInt("slot", i).apply()
                                },
                            contentAlignment = Alignment.Center,
                        ) {
                            SongText(
                                text = i.toString(),
                                size = 15.sp,
                                weight = FontWeight.SemiBold,
                                color = if (on) Color.White else Ink,
                            )
                        }
                    }
                }
                Spacer(Modifier.height(10.dp))
                SongText(
                    text = "当前槽位：" + slot.toString(),
                    size = 12.sp,
                    color = Jade,
                )
            }
            SectionTitle("防护构成")
            FeatureCard(
                "01",
                "本地检测对抗",
                "覆盖文件探测与目录列举、文件打开、命令执行、包名查询（含 13+ Flags 重载）、调试状态、系统属性、模拟器特征、进程与服务列表、堆栈痕迹、/proc 探针、内存映射与挂载表清洗（含 RandomAccessFile 路径）、框架类加载探测，另收敛 adb 与开发者选项等全局设置项。替换均为等长替换，不改返回值类型。",
            )
            Spacer(Modifier.height(10.dp))
            FeatureCard(
                "02",
                "设备指纹隔离",
                "以实例自身数据目录与实例 uid 派生种子，IMEI、IMSI、ICCID、android_id、序列号、MAC、蓝牙地址、MediaDrm 设备 ID、主机名逐实例独立；号码通过校验位规则，同一实例重启后保持不变。",
            )
            Spacer(Modifier.height(10.dp))
            FeatureCard(
                "03",
                "输入痕迹抹平",
                "清除事件上的注入标记位，虚拟设备号归一为触摸屏，自动点击与投屏类无障碍服务不出现在查询结果里，输入设备枚举里也看不到虚拟设备；坐标、时间、压力一概不动。",
            )
            Spacer(Modifier.height(10.dp))
            FeatureCard(
                "04",
                "网络出口清洗",
                "VPN 传输层标记、虚拟网卡、代理属性、系统代理设置项、路由表特征全部收敛为普通移动网络形态，只影响查询结果，不改变真实网络行为。",
            )

            SectionTitle("启用步骤")
            PaperCard {
                StepRow("一、", "在 LSPosed 中启用「异客防封」模块，并确认模块已激活。")
                StepRow("二、", "勾选作用域：勾上你实际安装的那个渠道（7 个包名可全选）。")
                StepRow("三、", "强制停止游戏后重新启动，模块在进程加载时完成注入。")
            }

            SectionTitle("生效验证")
            PaperCard {
                StepRow("一、", "打开 LSPosed 的日志页，筛选标签 [DFY]。")
                StepRow("二、", "启动光·遇后出现「[DFY] hooked into <对应渠道包名>」，说明模块已注入目标进程。")
                StepRow("三、", "若一条 [DFY] 记录都没有：模块未启用、作用域未勾选，或游戏进程未被真正重启。")
            }


            Spacer(Modifier.height(20.dp))
            Box(Modifier.fillMaxWidth().height(1.dp).background(Line))
            Spacer(Modifier.height(12.dp))
            SongText(
                "模块仅屏蔽游戏侧的本地环境查询，不修改游戏数据，不介入服务端通信。",
                size = 12.sp,
                color = Jade,
                lineHeight = 20.sp,
            )
            Spacer(Modifier.height(28.dp))
        }
        val info = update
        if (info != null) {
            AlertDialog(
                onDismissRequest = { update = null },
                containerColor = Card,
                title = {
                    SongText(
                        "发现新版本",
                        size = 18.sp,
                        weight = FontWeight.SemiBold,
                        color = Ink,
                    )
                },
                text = {
                    SongText(
                        text = listOf(
                            "版本号：" + info.code.toString(),
                            "版本名：" + info.name,
                            "",
                            "更新说明：",
                            info.changelog.ifEmpty { "无" },
                        ).joinToString("\n"),
                        size = 13.sp,
                        color = Ink,
                        lineHeight = 21.sp,
                    )
                },
                confirmButton = {
                    TextButton(onClick = {
                        openUrl(ctx, info.url)
                        update = null
                    }) {
                        SongText("更新", size = 14.sp, weight = FontWeight.SemiBold, color = Bronze)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { update = null }) {
                        SongText("下次再说", size = 14.sp, color = InkSoft)
                    }
                },
            )
        }
    }
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = AppColors, typography = SongTypography) {
                AppScreen()
            }
        }
    }
}

private data class UpdateInfo(
    val code: Int,
    val name: String,
    val changelog: String,
    val url: String,
)

/** 版本更新接口（接入文档：GET /api/app/version?package=&version_code=） */
private const val API_VERSION = "https://xn--us1a969a.top/api/app/version"

private fun openUrl(ctx: Context, url: String) {
    try {
        val i = Intent(Intent.ACTION_VIEW, Uri.parse(url))
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        ctx.startActivity(i)
    } catch (t: Throwable) {
        Toast.makeText(ctx, "没有可用的浏览器", Toast.LENGTH_SHORT).show()
    }
}

@Suppress("DEPRECATION")
private fun localVersionName(ctx: Context): String {
    return try {
        ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: "未知"
    } catch (t: Throwable) {
        "未知"
    }
}

@Suppress("DEPRECATION")
private fun localVersionCode(ctx: Context): Int {
    return try {
        val pi = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
        if (android.os.Build.VERSION.SDK_INT >= 28) pi.longVersionCode.toInt() else pi.versionCode
    } catch (t: Throwable) {
        0
    }
}

private fun checkUpdate(
    ctx: Context,
    onDone: (UpdateInfo?) -> Unit,
    onError: (String) -> Unit,
) {
    val localCode = localVersionCode(ctx)
    val pkg = ctx.packageName
    val code = localCode
    thread {
        var conn: HttpURLConnection? = null
        try {
            val url = URL(API_VERSION + "?package=" + pkg + "&version_code=" + code)
            conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.requestMethod = "GET"
            conn.setRequestProperty("Accept", "application/json")
            val text = conn.inputStream.bufferedReader().use { it.readText() }
            val root = JSONObject(text)
            if (root.optInt("code", 0) != 200) {
                onError(root.optString("message", "接口返回异常"))
                return@thread
            }
            val d = root.optJSONObject("data")
            if (d == null) {
                onDone(null)
                return@thread
            }
            val hasUpdate = d.optBoolean("has_update", false) ||
                d.optBoolean("need_update", false) ||
                d.optBoolean("update", false)
            if (!hasUpdate) {
                onDone(null)
                return@thread
            }
            val latestCode = d.optInt("latest_version_code", d.optInt("version_code", 0))
            val latestName = d.optString("latest_version_name", d.optString("version_name", ""))
            val changelog = d.optString("changelog", "")
            val link = d.optString("download_url", d.optString("url", ""))
            onDone(UpdateInfo(latestCode, latestName, changelog, link))
        } catch (t: Throwable) {
            onError("检测失败：" + (t.message ?: "网络异常"))
        } finally {
            try {
                conn?.disconnect()
            } catch (t: Throwable) {
            }
        }
    }
}
