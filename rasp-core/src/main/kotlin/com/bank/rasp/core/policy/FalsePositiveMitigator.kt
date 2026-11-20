package com.bank.rasp.core.policy

import kotlinx.serialization.Serializable
import com.bank.rasp.core.model.Signal

/**
 * 良性特征白名单条目。用于治理厂商定制 ROM / 老旧机型的误报。
 *
 * 设计要点：白名单只对**特定设备指纹 + 特定信号 ID**生效，且只能「降权」不能「删除」，
 * 这样即使白名单被滥用，强攻击的多信号收敛仍能阻断。
 */
@Serializable
data class AllowlistEntry(
    /** 匹配的设备指纹（Build.FINGERPRINT 的子串，或 "*" 表示全机型谨慎使用）。 */
    val deviceFingerprintContains: String,
    /** 命中后要降权的信号 ID。 */
    val signalId: String,
    /** 降权后的置信度上限。 */
    val capConfidence: Double,
    /** 人类可读原因，便于审计。 */
    val rationale: String
)

/**
 * 误报治理：应用白名单降权。注意它绝不删除信号，只压低置信度，
 * 并在证据里标注已被降权，保留可追溯性。
 */
class FalsePositiveMitigator(private val entries: List<AllowlistEntry>) {

    fun apply(deviceFingerprint: String, signals: List<Signal>): List<Signal> =
        signals.map { s ->
            val match = entries.firstOrNull {
                s.id == it.signalId &&
                    (it.deviceFingerprintContains == "*" ||
                        deviceFingerprint.contains(it.deviceFingerprintContains, ignoreCase = true))
            }
            if (match != null && s.confidence > match.capConfidence) {
                s.copy(
                    confidence = match.capConfidence,
                    evidence = "${s.evidence} [allowlisted:${match.rationale}]"
                )
            } else s
        }
}
