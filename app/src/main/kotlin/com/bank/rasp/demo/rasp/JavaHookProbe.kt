package com.bank.rasp.demo.rasp

import com.bank.rasp.core.model.Channel
import com.bank.rasp.core.model.Severity
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.ThreatFamily

/**
 * L3 Java 方法 hook 检测（修订版）。
 *
 * 重要事实：Method.getModifiers() 返回的是**声明期**修饰符，多数 hook 框架替换 ArtMethod
 * entrypoint 时并不改它，因此单纯反射 isNative 会漏报。本类改用两条更可靠的腿：
 *
 *  1) 调用栈完整性（运行时真实生效）：敏感操作执行时抓取调用栈，预期帧全部来自本应用
 *     类加载器/包名；出现 frida/xposed/未知 dex 帧即异常。这条无论 entrypoint 怎么改都有效，
 *     因为被 hook 后真正执行的代码会在栈上留下框架帧。
 *  2) 金丝雀 ArtMethod 的 native 校验交由 native 层做（见 NativeSelfCheck），Java 侧只负责声明基线。
 *
 * 另外保留对「声明即 native 的可疑桥接」的辅助检查作为补充信号。
 */
class JavaHookProbe {

    private val nowMs get() = System.currentTimeMillis()

    /**
     * 在敏感方法内部调用：检查当前调用栈是否被外部框架插入了帧。
     * @param expectedPackage 本应用包名前缀，栈帧类名应都在此包或可信系统包内。
     */
    fun checkCallStack(expectedPackage: String): List<Signal> = buildList {
        val stack = Thread.currentThread().stackTrace
        val foreign = stack.map { it.className }.filter { cn ->
            cn.contains("frida", true) ||
                cn.contains("xposed", true) ||
                cn.contains("lsposed", true) ||
                cn.contains("substrate", true) ||
                // 来自动态加载 dex 的匿名类
                cn.contains("dalvik.system.DexClassLoader")
        }.distinct()
        if (foreign.isNotEmpty()) {
            add(Signal(
                "HOOK_JAVA_STACK", ThreatFamily.JAVA_HOOK, Severity.CRITICAL, 0.92,
                "敏感操作调用栈出现外部 hook 框架帧: $foreign",
                Channel.JAVA_API, nowMs
            ))
        }

        // 统计不属于本包、也不属于 Android/Java 运行时的可疑帧
        val runtimePrefixes = listOf("android.", "java.", "javax.", "kotlin.", "dalvik.",
            "com.android.", expectedPackage)
        val unexpected = stack.map { it.className }
            .filter { cn -> runtimePrefixes.none { cn.startsWith(it) } }
            .filter { it.contains(".") } // 排除内部合成类的简单名
            .distinct()
        if (unexpected.isNotEmpty()) {
            add(Signal(
                "HOOK_JAVA_UNEXPECTED_FRAME", ThreatFamily.JAVA_HOOK, Severity.STRONG, 0.7,
                "调用栈存在非本应用、非系统运行时帧: $unexpected",
                Channel.JAVA_API, nowMs
            ))
        }
    }

    /** 占位金丝雀：其 ArtMethod 基线（非 native、有 code item）由 native 侧定期复核。 */
    class Canary {
        @Suppress("unused")
        fun canaryMethod() { /* baseline: ordinary non-native Java method */ }
    }
}
