package com.bank.rasp.demo.attack

import com.bank.rasp.core.model.Channel
import com.bank.rasp.core.model.Severity
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.ThreatFamily

/**
 * 模拟攻击的定义。
 *
 * 设计约束（合规与安全）：本模拟器只在**示例 App 自己的进程内**，通过向检测管线注入
 * 「攻击本应留下的可观测信号」来检验检测逻辑，不包含任何注入其它应用、绕过真实安全边界
 * 或攻击第三方的能力。它等价于一份「攻击痕迹样本 + 单元测试夹具」。
 *
 * 每类攻击都标注：真实世界对应手法、预期被哪一层/哪个 signal 抓住。
 */
enum class AttackType(
    val title: String,
    val realWorldTechnique: String,
    val expectedDetection: String
) {
    A1_JAVA_HOOK(
        "A1 Java 方法挂钩（篡改转账/跳过检查）",
        "Xposed/Frida 替换 TransferService 或 LocalSecurityChecks 的 ArtMethod",
        "L3 HOOK_JAVA_STACK / HOOK_JAVA_UNEXPECTED_FRAME + 金额完整性 AMOUNT_MISMATCH"
    ),
    A2_DETECTOR_SPOOF(
        "A2 检测 API 欺骗（hook 检测器本身返回干净）",
        "Frida 挂钩 EnvironmentProbe/读 maps 函数，使其返回无风险结果",
        "L4 多通道交叉验证：内容真矛盾→CROSS_CHANNEL_MISMATCH；通道沉默→CROSS_CHANNEL_GAP，配合注入框架多通道收敛阻断"
    ),
    A3_NATIVE_INLINE_HOOK(
        "A3 native inline hook（libc 函数打跳转桩）",
        "Frida Interceptor 在 open/read/ptrace 序言写 trampoline",
        "L3 HOOK_NATIVE_INLINE / HOOK_PTR_REDIRECT + L4 SELF_CRC_MISMATCH"
    ),
    A4_FRIDA_TRACES(
        "A4 Frida 痕迹注入（maps/线程名/默认端口）",
        "frida-agent 注入后在 maps、task comm、net/tcp 留下特征",
        "L2 INJECTION_LIB / FRIDA_THREAD / FRIDA_PORT，多通道收敛硬阻断"
    ),
    A5_EMULATOR_ROOT(
        "A5 模拟器 + Root 环境伪装",
        "改 Build 属性、su/Magisk 路径、虚拟化节点、缺失传感器",
        "L1 EMULATOR::* / ROOT_SU::*（弱信号，需多信号收敛才阻断）"
    ),
    A6_ATTESTATION_FRAUD(
        "A6 远程证明伪造（重放/篡改/无密钥签名）",
        "攻击者复用旧信封、改金额、或无设备私钥自造证明",
        "L5 服务端验签失败 / nonce 重放 Replayed / counter 回滚"
    )
}

/**
 * 攻击痕迹注入器：把某类攻击在真实环境会产生的信号注入检测管线。
 * 纯 Kotlin、无 Android 依赖，可在宿主机 JVM 单测中直接验证风险引擎反应。
 */
object AttackSimulator {

    /**
     * @param attack 攻击类型
     * @param nowMs 时间戳（注入以便测试）
     * @param partialSpoof 仅 A2 有效：true 表示只 hook 掉部分通道（更真实，会留下口径矛盾）
     */
    fun emit(attack: AttackType, nowMs: Long, partialSpoof: Boolean = true): List<Signal> =
        when (attack) {
            AttackType.A1_JAVA_HOOK -> a1JavaHook(nowMs)
            AttackType.A2_DETECTOR_SPOOF -> a2DetectorSpoof(nowMs, partialSpoof)
            AttackType.A3_NATIVE_INLINE_HOOK -> a3NativeInlineHook(nowMs)
            AttackType.A4_FRIDA_TRACES -> a4FridaTraces(nowMs)
            AttackType.A5_EMULATOR_ROOT -> a5EmulatorRoot(nowMs)
            AttackType.A6_ATTESTATION_FRAUD -> a6AttestationFraud(nowMs)
        }

    // A1：Java hook 在调用栈留下框架帧；同时金额被改（由 TransferRequest 体现）
    private fun a1JavaHook(nowMs: Long) = listOf(
        Signal("HOOK_JAVA_STACK", ThreatFamily.JAVA_HOOK, Severity.CRITICAL, 0.92,
            "敏感操作调用栈出现外部 hook 框架帧: [com.frida.Interceptor]",
            Channel.JAVA_API, nowMs),
        Signal("HOOK_JAVA_UNEXPECTED_FRAME", ThreatFamily.JAVA_HOOK, Severity.STRONG, 0.72,
            "调用栈存在非本应用帧: [com.frida.js.Bridge]", Channel.JAVA_API, nowMs)
    )

    // A2：攻击者 hook 掉 Java 通道让其沉默，但 proc/native 通道仍报出真实风险 → 口径矛盾
    private fun a2DetectorSpoof(nowMs: Long, partial: Boolean): List<Signal> {
        val out = mutableListOf<Signal>()
        // 真实的 Frida 仍在，native/proc 通道如实报出
        out += Signal("FRIDA_PRESENT::maps", ThreatFamily.INJECTION_FRAMEWORK,
            Severity.STRONG, 0.85, "maps 存在 frida-agent", Channel.NATIVE, nowMs)
        out += Signal("FRIDA_PRESENT::thread", ThreatFamily.INJECTION_FRAMEWORK,
            Severity.STRONG, 0.85, "线程 gum-js-loop", Channel.PROC_FS, nowMs)
        if (!partial) {
            // 极端情况：攻击者把能 hook 的通道全 hook 了，raw syscall 仍补一条
            out += Signal("FRIDA_PRESENT::raw", ThreatFamily.INJECTION_FRAMEWORK,
                Severity.STRONG, 0.85, "raw syscall 观测到注入", Channel.RAW_SYSCALL, nowMs)
        }
        // Java 通道被 hook 后「干净」沉默 —— CrossValidator 会发现期望通道缺失
        return out
    }

    // A3：libc 函数入口 trampoline + 函数体 CRC 变化（两条独立通道）
    private fun a3NativeInlineHook(nowMs: Long) = listOf(
        Signal("HOOK_NATIVE_INLINE::open", ThreatFamily.NATIVE_HOOK, Severity.CRITICAL, 0.92,
            "open 入口匹配跳转桩 LDR X16;BR X16", Channel.NATIVE, nowMs),
        Signal("SELF_CRC_MISMATCH::open", ThreatFamily.TAMPERED_DETECTOR, Severity.CRITICAL, 0.95,
            "open 函数体 CRC 基线=123456 当前=987654", Channel.RAW_SYSCALL, nowMs)
    )

    // A4：Frida 三类痕迹，跨 maps/线程/端口多源
    private fun a4FridaTraces(nowMs: Long) = listOf(
        Signal("INJECTION_LIB::/data/tmp/frida-agent-64.so", ThreatFamily.INJECTION_FRAMEWORK,
            Severity.CRITICAL, 0.95, "内存映射出现 frida-agent", Channel.PROC_FS, nowMs),
        Signal("FRIDA_THREAD::gum-js-loop", ThreatFamily.INJECTION_FRAMEWORK,
            Severity.STRONG, 0.85, "特征线程 gum-js-loop", Channel.PROC_FS, nowMs),
        Signal("FRIDA_PORT::69A2", ThreatFamily.INJECTION_FRAMEWORK,
            Severity.STRONG, 0.8, "Frida 默认端口 27042", Channel.PROC_FS, nowMs),
        Signal("FRIDA_PRESENT::maps", ThreatFamily.INJECTION_FRAMEWORK,
            Severity.STRONG, 0.85, "native 通道确认注入", Channel.NATIVE, nowMs)
    )

    // A5：模拟器/root 弱信号群（单条不阻断，演示误报治理与收敛）
    private fun a5EmulatorRoot(nowMs: Long) = listOf(
        Signal("EMULATOR::build", ThreatFamily.EMULATOR, Severity.WEAK, 0.5,
            "Build 命中 generic/goldfish", Channel.JAVA_API, nowMs),
        Signal("EMULATOR::driver", ThreatFamily.EMULATOR, Severity.WEAK, 0.7,
            "存在 /dev/goldfish_pipe", Channel.PROC_FS, nowMs),
        Signal("EMU_SENSOR_MISSING", ThreatFamily.EMULATOR, Severity.WEAK, 0.45,
            "加速度/陀螺仪缺失", Channel.HARDWARE, nowMs),
        Signal("ROOT_SU::path", ThreatFamily.ROOT, Severity.WEAK, 0.6,
            "发现 /sbin/su", Channel.PROC_FS, nowMs),
        Signal("ROOT_SU::magisk", ThreatFamily.ROOT, Severity.WEAK, 0.6,
            "发现 /data/adb/magisk", Channel.PROC_FS, nowMs)
    )

    // A6：客户端无法本地产生该信号，这里只表达「服务端侧会观察到的伪造尝试」标签，
    // 真正的检验在 mock-server 的验签/nonce/counter 逻辑与端到端测试里。
    private fun a6AttestationFraud(nowMs: Long) = listOf(
        Signal("ATTESTATION_FRAUD::attempt", ThreatFamily.ATTESTATION_FRAUD,
            Severity.INFO, 0.5, "观测到证明伪造尝试（服务端判定）", Channel.REMOTE_POLICY, nowMs)
    )
}
