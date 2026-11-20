package com.bank.rasp.core.engine

import com.bank.rasp.core.model.Channel
import com.bank.rasp.core.model.Severity
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.ThreatFamily

/**
 * 多通道交叉验证器。
 *
 * 核心思想：注入工具往往只 hook 最表层的 API（如 Java 的 Build 属性、libc 的 open/read），
 * 很难同时让 Java API、/proc 文件、native raw syscall 等相互独立的通道「口径一致」。
 *
 * 关键的反误报区分（两类证据强度完全不同）：
 *  1) 「同一工件经两条通道读取，内容真的矛盾」—— 这是强篡改证据，由调用方
 *     （如 InjectionProbe 比对同一份 maps 的哈希）以 STRONG 信号上报，本类不负责。
 *  2) 「某条期望通道只是沉默、没有报信号」—— 这只构成【通道缺口】线索：探针本来就可能
 *     在某通道上查不到证据，不能等同于「该通道被 hook 说谎」。因此本类只产出 WEAK、
 *     低置信（0.4）信号，绝不单独满足风险引擎的硬阻断规则（硬阻断要求置信≥0.8）。
 *
 * 用「分组键」描述「同一个事实」：同一 group、不同 channel 的信号归入同一事实组。
 */
object CrossValidator {

    /**
     * 把信号映射到「事实组」。约定：需要交叉验证的信号 id 形如 "<GROUP>::<detail>"，
     * 例如 "ROOT_SU::java" / "ROOT_SU::proc"。不含 "::" 的信号不参与交叉验证。
     */
    fun groupKey(signal: Signal): String? {
        val idx = signal.id.indexOf("::")
        return if (idx > 0) signal.id.substring(0, idx) else null
    }

    /**
     * @param expectedChannels 每个事实组理论上可覆盖的通道；仅当某组已有高置信信号、
     *        而其它期望通道集体沉默时，才给出一条低置信「通道缺口」提示。
     */
    fun validate(
        signals: List<Signal>,
        expectedChannels: Map<String, Set<Channel>>,
        timestampMs: Long
    ): List<Signal> {
        val gaps = mutableListOf<Signal>()
        val byGroup = signals.mapNotNull { s -> groupKey(s)?.let { it to s } }.groupBy({ it.first }, { it.second })

        for ((group, groupSignals) in byGroup) {
            val expected = expectedChannels[group] ?: continue
            if (expected.size < 2) continue
            val presentChannels = groupSignals.map { it.channel }.toSet()
            val missing = expected - presentChannels
            // 只有当该事实组已存在【高置信(≥0.8)】风险信号、而别的期望通道却集体沉默时，
            // 才提示通道缺口；弱信号组不报，避免在正常/弱风险机型上制造误报。
            val hasStrong = groupSignals.any { it.confidence >= 0.8 }
            if (hasStrong && missing.isNotEmpty()) {
                gaps += Signal(
                    id = "CROSS_CHANNEL_GAP::$group",
                    family = ThreatFamily.TAMPERED_DETECTOR,
                    severity = Severity.WEAK,
                    confidence = 0.4,
                    evidence = "事实组 $group 在通道 $presentChannels 出现高置信信号，" +
                        "但期望通道 $missing 沉默，存在通道缺口（线索，非定论）",
                    channel = Channel.RAW_SYSCALL,
                    timestampMs = timestampMs
                )
            }
        }
        return gaps
    }
}
