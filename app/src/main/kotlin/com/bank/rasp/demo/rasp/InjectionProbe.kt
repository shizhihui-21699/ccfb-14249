package com.bank.rasp.demo.rasp

import com.bank.rasp.core.model.Channel
import com.bank.rasp.core.model.Severity
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.ThreatFamily
import java.io.File

/**
 * L2 注入/Hook 框架检测。
 *
 * 多通道：native(raw/proc) 为主，Java 层补充 Xposed 栈/类检测，并对「同一事实」
 * 用统一的 group id（FRIDA_PRESENT::* / ROOT_SU::java 等），供 rasp-core 的 CrossValidator
 * 判断各通道口径是否一致——某通道被 hook 沉默时会暴露矛盾。
 */
class InjectionProbe {

    private val nowMs get() = System.currentTimeMillis()

    fun run(): List<Signal> = buildList {
        // 1) native 通道：maps / 线程名 / 端口 / 匿名可执行页 / inline hook
        if (NativeBridge.isAvailable) {
            val nativeFindings = runCatching { NativeBridge.nativeRunAll() }
                .getOrDefault(emptyArray())
            addAll(ProbeMapper.toSignals(nativeFindings, nowMs))
        } else {
            // so 加载失败：可能被攻击者阻止，也可能是打包问题；给中低置信信号并标注
            add(Signal("NATIVE_LIB_MISSING", ThreatFamily.TAMPERED_DETECTOR, Severity.WEAK,
                0.5, "rasp_native 库未能加载，native 探针缺失", Channel.NATIVE, nowMs))
        }

        // 2) Java 通道：Xposed / LSPosed 桥接类与调用栈
        addAll(xposedSignals())

        // 3) 多通道交叉验证的 Java 侧补点：用 Java File API 读一次 maps，
        //    与 native raw syscall 读到的内容做一致性比对（不一致即检测通道被篡改）
        addAll(mapsCrossChannel())
    }

    private fun xposedSignals(): List<Signal> = buildList {
        // 尝试加载 Xposed 桥类；正常设备上应失败
        val bridgeClass = try {
            Class.forName("de.robv.android.xposed.XposedBridge")
        } catch (_: Throwable) {
            null
        }
        if (bridgeClass != null) {
            add(Signal("XPOSED_BRIDGE_PRESENT", ThreatFamily.INJECTION_FRAMEWORK,
                Severity.STRONG, 0.85, "类路径中存在 XposedBridge", Channel.JAVA_API, nowMs))
        }
        val lsposed = try {
            Class.forName("org.lsposed.hiddenapibypass.HiddenApiBypass")
            Class.forName("org.lsposed.lspd.service.ILSPApplicationService")
        } catch (_: Throwable) {
            null
        }
        if (lsposed != null) {
            add(Signal("XPOSED_BRIDGE_PRESENT::lsposed", ThreatFamily.INJECTION_FRAMEWORK,
                Severity.STRONG, 0.85, "检测到 LSPosed 服务类", Channel.JAVA_API, nowMs))
        }
        // 当前调用栈里若出现 xposed 包，说明本线程正被框架拦截
        val stack = Thread.currentThread().stackTrace.map { it.className }
        if (stack.any { it.contains("xposed", true) || it.contains("lsposed", true) }) {
            add(Signal("XPOSED_STACK_FRAME", ThreatFamily.INJECTION_FRAMEWORK,
                Severity.CRITICAL, 0.9, "调用栈出现 Xposed/LSPosed 帧", Channel.JAVA_API, nowMs))
        }
    }

    /**
     * 同一 maps 用两条独立通道读取：Java File API（可被 hook）与 native raw syscall（难 hook）。
     *
     * 反误报要点：不能直接比对两份 maps 的全文哈希——两次读取之间，干净设备也可能因内存分配、
     * JIT、线程栈变化导致匿名段/地址列不同，从而误报。这里只比对**与攻击相关的稳定特征**：
     * 提取各自文本里的「注入库标记」集合，若 raw 通道看到某注入库、Java 通道却把它隐藏掉
     * （非对称差异），才判定读取通道被篡改。良性的映射抖动不包含注入标记，不会触发。
     */
    private fun mapsCrossChannel(): List<Signal> = buildList {
        if (!NativeBridge.isAvailable) return@buildList
        val viaJava = runCatching { File("/proc/self/maps").readText() }.getOrNull() ?: return@buildList
        val viaNative = NativeBridge.nativeReadProc("/proc/self/maps") ?: return@buildList

        val javaMarkers = injectionMarkers(viaJava)
        val nativeMarkers = injectionMarkers(viaNative)
        // raw 通道独有、被 Java 通道「抹掉」的注入标记 → 强证据
        val hiddenByJava = nativeMarkers - javaMarkers
        if (hiddenByJava.isNotEmpty()) {
            add(Signal(
                "CROSS_CHANNEL_MISMATCH::maps",
                ThreatFamily.TAMPERED_DETECTOR, Severity.STRONG, 0.9,
                "raw syscall 读到注入标记 $hiddenByJava，但 Java File API 的结果中被隐藏，读取通道被 hook",
                Channel.RAW_SYSCALL, nowMs
            ))
        }
    }

    /** 从 maps 文本中提取注入/hook 框架库标记（与 native scanners 的关键字保持一致）。 */
    private fun injectionMarkers(mapsText: String): Set<String> {
        val needles = listOf(
            "frida-agent", "libfrida", "frida-gadget", "linjector", "libgadget",
            "xposed", "lsposed", "substrate", "edxposed", "riru", "zygisk", "shamiko", "magisk"
        )
        val lower = mapsText.lowercase()
        return needles.filter { lower.contains(it) }.toSet()
    }
}
