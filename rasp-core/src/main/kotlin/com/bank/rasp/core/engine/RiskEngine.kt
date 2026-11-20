package com.bank.rasp.core.engine

import com.bank.rasp.core.model.Channel
import com.bank.rasp.core.model.Reason
import com.bank.rasp.core.model.Severity
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.ThreatFamily
import com.bank.rasp.core.model.Verdict
import com.bank.rasp.core.model.VerdictLevel
import com.bank.rasp.core.policy.RiskPolicy

/**
 * 风险引擎：纯函数式聚合，不接触 Android API，因此可在宿主机 JVM 完整单测。
 *
 * 评分：每条信号 = 严重级别基础分 × 置信度 × 威胁族权重，同族取贡献最大的若干条，
 * 叠加多信号收敛加成。最终映射到等级；满足收敛硬规则时直接 BLOCK。
 */
class RiskEngine(private val policy: RiskPolicy = RiskPolicy()) {

    fun evaluate(signals: List<Signal>): Verdict {
        if (signals.isEmpty()) return Verdict.CLEAN

        val reasons = mutableListOf<Reason>()
        var rawScore = 0.0

        // 同族内做边际递减，避免同一威胁刷大量同质信号把分数线性顶满
        val byFamily = signals.groupBy { it.family }
        for ((family, familySignals) in byFamily) {
            val weight = policy.familyWeight[family] ?: 1.0
            val sorted = familySignals.sortedByDescending { contribution(it) }
            sorted.forEachIndexed { index, s ->
                val decay = 1.0 / (1.0 + index * 0.5) // 第 1 条 100%，第 2 条 67%，第 3 条 50%...
                rawScore += contribution(s) * weight * decay
            }
        }

        // 多信号收敛硬阻断规则
        var forceBlock = false
        for (rule in policy.convergenceRules) {
            val relevant = signals.filter {
                it.family == rule.family && it.confidence >= rule.minConfidence
            }
            val distinctChannels = relevant.map { it.channel }.toSet().size
            if (relevant.size >= rule.minSignals && distinctChannels >= rule.distinctChannels) {
                forceBlock = true
                reasons += Reason(
                    signalId = "CONVERGENCE::${rule.family}",
                    family = rule.family,
                    detail = "威胁族 ${rule.family} 在 $distinctChannels 条独立通道、" +
                        "${relevant.size} 条高置信信号上收敛，触发硬阻断"
                )
            }
        }

        val score = rawScore.toInt().coerceIn(0, 100)
        val level = when {
            forceBlock || score >= policy.blockAt -> VerdictLevel.BLOCK
            score >= policy.highAt -> VerdictLevel.HIGH
            score >= policy.mediumAt -> VerdictLevel.MEDIUM
            score >= policy.lowAt -> VerdictLevel.LOW
            else -> VerdictLevel.NONE
        }

        // 记录贡献最大的若干条作为可解释理由（去重、限量，避免上报膨胀）
        signals.sortedByDescending { contribution(it) }.take(8).forEach {
            reasons += Reason(it.id, it.family, "${it.evidence} (ch=${it.channel},conf=${it.confidence})")
        }

        return Verdict(
            level = level,
            score = score,
            reasons = reasons.distinctBy { it.signalId }.take(10),
            families = byFamily.keys
        )
    }

    private fun contribution(s: Signal): Double {
        val base = policy.severityBase[s.severity] ?: 0
        return base * s.confidence
    }

    /** 供测试 / 调试用：列出某等级阈值。 */
    fun thresholdFor(level: VerdictLevel): Int = when (level) {
        VerdictLevel.NONE -> 0
        VerdictLevel.LOW -> policy.lowAt
        VerdictLevel.MEDIUM -> policy.mediumAt
        VerdictLevel.HIGH -> policy.highAt
        VerdictLevel.BLOCK -> policy.blockAt
    }

    companion object {
        /** 事实组 → 期望覆盖的独立通道，用于交叉验证。集中声明便于审计。 */
        val EXPECTED_CHANNELS: Map<String, Set<Channel>> = mapOf(
            "ROOT_SU" to setOf(Channel.JAVA_API, Channel.PROC_FS, Channel.NATIVE),
            "FRIDA_PRESENT" to setOf(Channel.PROC_FS, Channel.NATIVE, Channel.RAW_SYSCALL),
            "EMULATOR" to setOf(Channel.JAVA_API, Channel.HARDWARE, Channel.PROC_FS),
            "DEBUGGER" to setOf(Channel.JAVA_API, Channel.NATIVE, Channel.RAW_SYSCALL)
        )
    }
}
