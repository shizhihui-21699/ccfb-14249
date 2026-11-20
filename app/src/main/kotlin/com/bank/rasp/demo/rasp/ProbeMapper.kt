package com.bank.rasp.demo.rasp

import com.bank.rasp.core.model.Channel
import com.bank.rasp.core.model.Severity
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.ThreatFamily

/**
 * 把 native 字符串枚举安全映射到 rasp-core 的强类型枚举。
 * 任何无法识别的值都退回到最保守的默认，绝不因解析异常导致检测崩溃（崩溃会被攻击者利用做 DoS）。
 */
object ProbeMapper {

    fun toSignals(findings: Array<NativeFinding>, nowMs: Long): List<Signal> =
        findings.map { f ->
            Signal(
                id = f.id,
                family = family(f.family),
                severity = severity(f.severity),
                confidence = f.confidence.coerceIn(0.0, 1.0),
                evidence = f.evidence,
                channel = channel(f.channel),
                timestampMs = nowMs
            )
        }

    private fun family(v: String): ThreatFamily =
        runCatching { ThreatFamily.valueOf(v) }.getOrDefault(ThreatFamily.INJECTION_FRAMEWORK)

    private fun severity(v: String): Severity =
        runCatching { Severity.valueOf(v) }.getOrDefault(Severity.WEAK)

    private fun channel(v: String): Channel =
        runCatching { Channel.valueOf(v) }.getOrDefault(Channel.NATIVE)
}
