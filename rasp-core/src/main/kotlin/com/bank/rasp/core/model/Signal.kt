package com.bank.rasp.core.model

import kotlinx.serialization.Serializable

/**
 * 检测通道：同一个事实尽量用多条相互独立的通道采集，
 * 以便在 [com.bank.rasp.core.engine] 中做交叉验证。
 */
@Serializable
enum class Channel {
    JAVA_API,        // Android Framework / Java 层 API（最容易被 hook）
    PROC_FS,         // 直接读取 /proc、/sys 等文件
    NATIVE,          // JNI native 探针
    RAW_SYSCALL,     // 绕过 libc 的裸系统调用（最难在用户态被 hook）
    HARDWARE,        // 传感器 / CPU / 硬件特征
    STATIC_BASELINE, // APK 内置基线（签名、预期 CRC 等）
    REMOTE_POLICY    // 服务端下发策略
}

/** 威胁族，用于把多个探针的信号收敛成同一类结论。 */
@Serializable
enum class ThreatFamily {
    EMULATOR,
    ROOT,
    DEBUGGER,
    INJECTION_FRAMEWORK,   // Frida / Xposed / LSPosed 等
    JAVA_HOOK,
    NATIVE_HOOK,
    TAMPERED_DETECTOR,     // 检测器自身被改 / 多通道不一致
    REPACKAGING,
    ATTESTATION_FRAUD
}

/** 严重级别（单条信号的固有强度）。 */
@Serializable
enum class Severity { INFO, WEAK, STRONG, CRITICAL }

/**
 * 一条检测信号。探针只负责如实产出信号 + 证据，不做最终阻断决策
 * （决策在 [com.bank.rasp.core.engine.RiskEngine]，便于集中灰度调参、治理误报）。
 */
@Serializable
data class Signal(
    /** 稳定的信号 ID，例如 HOOK_NATIVE_INLINE。服务端策略据此匹配。 */
    val id: String,
    val family: ThreatFamily,
    val severity: Severity,
    /** 0.0~1.0，探针自评置信度。命中硬特征给高值，间接推测给低值。 */
    val confidence: Double,
    /** 命中的客观证据（不含用户隐私），用于研判与误报分析。 */
    val evidence: String,
    val channel: Channel,
    /** 采集时间戳（毫秒）。由调用方注入，核心层不直接依赖时钟以便测试。 */
    val timestampMs: Long
) {
    init {
        require(confidence in 0.0..1.0) { "confidence 必须在 [0,1]：$confidence" }
    }
}

/** 最终裁决等级。 */
@Serializable
enum class VerdictLevel { NONE, LOW, MEDIUM, HIGH, BLOCK }

/** 触发某条裁决理由的信号引用。 */
@Serializable
data class Reason(val signalId: String, val family: ThreatFamily, val detail: String)

@Serializable
data class Verdict(
    val level: VerdictLevel,
    /** 0~100 的风险分，便于服务端设连续阈值与灰度。 */
    val score: Int,
    val reasons: List<Reason>,
    /** 命中的威胁族，供服务端统计。 */
    val families: Set<ThreatFamily>
) {
    /** 敏感操作是否应在本地被 fail-closed 中止。 */
    val shouldBlockSensitive: Boolean get() = level == VerdictLevel.BLOCK

    companion object {
        val CLEAN = Verdict(VerdictLevel.NONE, 0, emptyList(), emptySet())
    }
}
