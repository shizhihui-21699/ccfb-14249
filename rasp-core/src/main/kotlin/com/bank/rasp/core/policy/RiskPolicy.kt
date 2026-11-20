package com.bank.rasp.core.policy

import com.bank.rasp.core.model.Severity
import com.bank.rasp.core.model.ThreatFamily
import kotlinx.serialization.Serializable

/**
 * 风险策略：阈值与各威胁族权重集中在此，可由服务端下发覆盖本地默认值，
 * 从而在不发版的情况下灰度调整误报/漏报平衡。
 */
@Serializable
data class RiskPolicy(
    /** 各裁决等级的分数下界（含）。 */
    val lowAt: Int = 15,
    val mediumAt: Int = 40,
    val highAt: Int = 65,
    val blockAt: Int = 85,
    /** 单条信号基础分，按严重级别。 */
    val severityBase: Map<Severity, Int> = mapOf(
        Severity.INFO to 2,
        Severity.WEAK to 12,
        Severity.STRONG to 35,
        Severity.CRITICAL to 60
    ),
    /**
     * 威胁族权重。TAMPERED_DETECTOR / NATIVE_HOOK / INJECTION_FRAMEWORK 权重最高，
     * 因为它们直接意味着运行时被操控。
     */
    val familyWeight: Map<ThreatFamily, Double> = mapOf(
        ThreatFamily.EMULATOR to 1.0,
        ThreatFamily.ROOT to 1.0,
        ThreatFamily.DEBUGGER to 1.1,
        ThreatFamily.INJECTION_FRAMEWORK to 1.3,
        ThreatFamily.JAVA_HOOK to 1.2,
        ThreatFamily.NATIVE_HOOK to 1.4,
        ThreatFamily.TAMPERED_DETECTOR to 1.5,
        ThreatFamily.REPACKAGING to 1.3,
        ThreatFamily.ATTESTATION_FRAUD to 1.5
    ),
    /**
     * 自动硬阻断规则：当某个威胁族在【至少 distinctChannels 条不同通道】上
     * 出现【至少 minSignals 条】置信度≥minConfidence 的信号时，无论总分是否到 blockAt，
     * 直接 BLOCK。这是「多信号收敛才阻断」的核心，避免单点误报。
     */
    val convergenceRules: List<ConvergenceRule> = listOf(
        ConvergenceRule(ThreatFamily.NATIVE_HOOK, minSignals = 2, distinctChannels = 2, minConfidence = 0.7),
        ConvergenceRule(ThreatFamily.INJECTION_FRAMEWORK, minSignals = 2, distinctChannels = 2, minConfidence = 0.6),
        ConvergenceRule(ThreatFamily.TAMPERED_DETECTOR, minSignals = 1, distinctChannels = 1, minConfidence = 0.8),
        ConvergenceRule(ThreatFamily.REPACKAGING, minSignals = 1, distinctChannels = 1, minConfidence = 0.9)
    )
)

@Serializable
data class ConvergenceRule(
    val family: ThreatFamily,
    val minSignals: Int,
    val distinctChannels: Int,
    val minConfidence: Double
)
