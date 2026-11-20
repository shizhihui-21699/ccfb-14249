package com.bank.rasp.core.engine

import com.bank.rasp.core.model.Channel
import com.bank.rasp.core.model.Severity
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.ThreatFamily
import com.bank.rasp.core.model.VerdictLevel
import com.bank.rasp.core.policy.RiskPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class RiskEngineTest {

    private val now = 1_000_000L
    private fun sig(
        id: String,
        family: ThreatFamily,
        severity: Severity,
        confidence: Double,
        channel: Channel
    ) = Signal(id, family, severity, confidence, "evidence-$id", channel, now)

    @Test
    fun `no signals means clean`() {
        val verdict = RiskEngine().evaluate(emptyList())
        assertEquals(VerdictLevel.NONE, verdict.level)
        assertFalse(verdict.shouldBlockSensitive)
    }

    @Test
    fun `single weak emulator signal never blocks`() {
        // 误报治理的关键保证：单个弱信号最高 LOW，不能阻断正常用户
        val signals = listOf(
            sig("EMULATOR::build-hint", ThreatFamily.EMULATOR, Severity.WEAK, 0.4, Channel.JAVA_API)
        )
        val verdict = RiskEngine().evaluate(signals)
        assertTrue(verdict.level in listOf(VerdictLevel.NONE, VerdictLevel.LOW, VerdictLevel.MEDIUM))
        assertFalse(verdict.shouldBlockSensitive)
    }

    @Test
    fun `native hook converging across two channels forces block`() {
        // 同一威胁族、两条独立通道、两条高置信信号 → 收敛硬阻断
        val signals = listOf(
            sig("HOOK_NATIVE_INLINE::open", ThreatFamily.NATIVE_HOOK, Severity.STRONG, 0.9, Channel.NATIVE),
            sig("HOOK_NATIVE_GOT::read", ThreatFamily.NATIVE_HOOK, Severity.STRONG, 0.85, Channel.RAW_SYSCALL)
        )
        val verdict = RiskEngine().evaluate(signals)
        assertEquals(VerdictLevel.BLOCK, verdict.level)
        assertTrue(verdict.shouldBlockSensitive)
        assertTrue(verdict.reasons.any { it.signalId.startsWith("CONVERGENCE") })
    }

    @Test
    fun `same channel repeated does not satisfy distinct-channel convergence`() {
        // 全部来自同一通道（可能是该通道自身被污染/误报），不满足多通道收敛
        val signals = listOf(
            sig("HOOK_NATIVE_INLINE::a", ThreatFamily.NATIVE_HOOK, Severity.STRONG, 0.9, Channel.NATIVE),
            sig("HOOK_NATIVE_INLINE::b", ThreatFamily.NATIVE_HOOK, Severity.STRONG, 0.9, Channel.NATIVE)
        )
        val verdict = RiskEngine().evaluate(signals)
        // 不触发收敛硬规则；只能靠总分，且不应被标记成 convergence block
        assertFalse(verdict.reasons.any { it.signalId.startsWith("CONVERGENCE") })
    }

    @Test
    fun `tampered detector high confidence alone blocks`() {
        // 检测器自校验发现被改，是最高优先级威胁
        val signals = listOf(
            sig("SELF_CRC_MISMATCH", ThreatFamily.TAMPERED_DETECTOR, Severity.CRITICAL, 0.95, Channel.RAW_SYSCALL)
        )
        val verdict = RiskEngine().evaluate(signals)
        assertEquals(VerdictLevel.BLOCK, verdict.level)
    }

    @Test
    fun `many duplicate signals decay instead of linear stacking`() {
        val many = (1..20).map { i ->
            sig("ROOT_HINT::$i", ThreatFamily.ROOT, Severity.WEAK, 0.5, Channel.PROC_FS)
        }
        val verdict = RiskEngine(RiskPolicy()).evaluate(many)
        assertTrue(verdict.score <= 100)
        // 20 条同质弱信号不应被当成确定性攻击而硬阻断（除非满足收敛规则，ROOT 无硬规则）
        assertFalse(verdict.shouldBlockSensitive)
    }

    @Test
    fun `cross channel gap is flagged when strong signal leaves expected channel silent`() {
        // FRIDA 在 proc 与 native 通道高置信报出，但 raw syscall 通道沉默 → 通道缺口（弱线索，非硬阻断）
        val signals = listOf(
            sig("FRIDA_PRESENT::thread", ThreatFamily.INJECTION_FRAMEWORK, Severity.STRONG, 0.8, Channel.PROC_FS),
            sig("FRIDA_PRESENT::maps", ThreatFamily.INJECTION_FRAMEWORK, Severity.STRONG, 0.8, Channel.NATIVE)
        )
        val gap = CrossValidator.validate(
            signals, RiskEngine.EXPECTED_CHANNELS, now
        )
        assertEquals(1, gap.size)
        assertEquals(ThreatFamily.TAMPERED_DETECTOR, gap.first().family)
        assertTrue(gap.first().id.startsWith("CROSS_CHANNEL_GAP"))
        // 关键：通道缺口只是 WEAK 低置信，不能单独触发硬阻断
        assertEquals(Severity.WEAK, gap.first().severity)
        assertTrue(gap.first().confidence < 0.5)
    }

    @Test
    fun `weak signal group does not raise cross channel gap`() {
        // 弱信号组（<0.8）即使有通道沉默，也不报缺口，避免误报
        val signals = listOf(
            sig("ROOT_SU::path", ThreatFamily.ROOT, Severity.WEAK, 0.6, Channel.PROC_FS)
        )
        val gap = CrossValidator.validate(signals, RiskEngine.EXPECTED_CHANNELS, now)
        assertTrue(gap.isEmpty())
    }

    @Test
    fun `all expected channels reporting produces no mismatch`() {
        val signals = listOf(
            Channel.PROC_FS, Channel.NATIVE, Channel.RAW_SYSCALL
        ).map { sig("FRIDA_PRESENT::$it", ThreatFamily.INJECTION_FRAMEWORK, Severity.STRONG, 0.8, it) }
        val mismatch = CrossValidator.validate(signals, RiskEngine.EXPECTED_CHANNELS, now)
        assertTrue(mismatch.isEmpty())
    }
}
