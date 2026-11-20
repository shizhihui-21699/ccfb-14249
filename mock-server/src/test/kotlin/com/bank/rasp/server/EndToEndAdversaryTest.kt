package com.bank.rasp.server

import com.bank.rasp.core.attestation.AttestationPayload
import com.bank.rasp.core.attestation.AttestationSigner
import com.bank.rasp.core.attestation.CounterGuard
import com.bank.rasp.core.attestation.NonceService
import com.bank.rasp.core.attestation.SoftwareRsaSigner
import com.bank.rasp.core.engine.CrossValidator
import com.bank.rasp.core.engine.RiskEngine
import com.bank.rasp.core.model.Channel
import com.bank.rasp.core.model.Severity
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.ThreatFamily
import com.bank.rasp.core.model.VerdictLevel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertContains
import kotlin.test.assertTrue

/**
 * 端到端对抗测试（纯 JVM，无需设备/模拟器）：
 * 用 AttackSimulator 的信号样本驱动「风险引擎 + 交叉验证 + 远程证明 + 服务端裁决」全链路，
 * 验证每一类攻击都能被正确阻断，且干净设备不会被误杀。
 *
 * 注：AttackSimulator 在 app 模块（Android），这里复制等价的信号构造，
 * 使该测试可独立在 JVM 运行，CI 无需 Android SDK。
 */
class EndToEndAdversaryTest {

    private val now = 10_000_000L
    private val engine = RiskEngine()

    // 与 app 模块 AttackSimulator 等价的攻击痕迹
    private fun attackTraces(kind: String): List<Signal> = when (kind) {
        "A1" -> listOf(
            Signal("HOOK_JAVA_STACK", ThreatFamily.JAVA_HOOK, Severity.CRITICAL, 0.92,
                "frida frame", Channel.JAVA_API, now),
            Signal("HOOK_JAVA_UNEXPECTED_FRAME", ThreatFamily.JAVA_HOOK, Severity.STRONG, 0.72,
                "foreign frame", Channel.JAVA_API, now)
        )
        "A2" -> listOf(
            // Java 通道被 hook 沉默，只剩 native/proc 报真实风险
            Signal("FRIDA_PRESENT::maps", ThreatFamily.INJECTION_FRAMEWORK, Severity.STRONG, 0.85,
                "frida-agent", Channel.NATIVE, now),
            Signal("FRIDA_PRESENT::thread", ThreatFamily.INJECTION_FRAMEWORK, Severity.STRONG, 0.85,
                "gum-js-loop", Channel.PROC_FS, now)
        )
        "A3" -> listOf(
            Signal("HOOK_NATIVE_INLINE::open", ThreatFamily.NATIVE_HOOK, Severity.CRITICAL, 0.92,
                "trampoline", Channel.NATIVE, now),
            Signal("SELF_CRC_MISMATCH::open", ThreatFamily.TAMPERED_DETECTOR, Severity.CRITICAL, 0.95,
                "crc changed", Channel.RAW_SYSCALL, now)
        )
        "A4" -> listOf(
            Signal("INJECTION_LIB::frida-agent", ThreatFamily.INJECTION_FRAMEWORK, Severity.CRITICAL, 0.95,
                "frida", Channel.PROC_FS, now),
            Signal("FRIDA_THREAD::gum-js-loop", ThreatFamily.INJECTION_FRAMEWORK, Severity.STRONG, 0.85,
                "thread", Channel.PROC_FS, now),
            Signal("FRIDA_PORT::69A2", ThreatFamily.INJECTION_FRAMEWORK, Severity.STRONG, 0.8,
                "port", Channel.PROC_FS, now),
            Signal("FRIDA_PRESENT::maps", ThreatFamily.INJECTION_FRAMEWORK, Severity.STRONG, 0.85,
                "native confirm", Channel.NATIVE, now)
        )
        "A5" -> listOf(
            Signal("EMULATOR::build", ThreatFamily.EMULATOR, Severity.WEAK, 0.5, "generic", Channel.JAVA_API, now),
            Signal("EMULATOR::driver", ThreatFamily.EMULATOR, Severity.WEAK, 0.7, "goldfish", Channel.PROC_FS, now),
            Signal("ROOT_SU::path", ThreatFamily.ROOT, Severity.WEAK, 0.6, "su", Channel.PROC_FS, now)
        )
        else -> emptyList()
    }

    private fun fullSignals(kind: String): List<Signal> {
        val raw = attackTraces(kind)
        // 叠加交叉验证结果（A2 的关键：被隐藏通道产生 mismatch）
        val mismatch = CrossValidator.validate(raw, RiskEngine.EXPECTED_CHANNELS, now)
        return raw + mismatch
    }

    @Test
    fun `A1 java hook is blocked`() {
        val v = engine.evaluate(fullSignals("A1"))
        assertEquals(VerdictLevel.BLOCK, v.level)
    }

    @Test
    fun `A2 detector spoofing surfaces cross-channel gap and blocks via injection convergence`() {
        val signals = fullSignals("A2")
        // 即使 Java 检测 API 被 hook 成「干净」，交叉验证仍标出通道缺口线索
        assertTrue(signals.any { it.id.startsWith("CROSS_CHANNEL_GAP") })
        // 真正的硬阻断来自注入框架在 native/proc 两条独立通道的高置信收敛，
        // 而不是依赖那条被降级的弱线索
        val v = engine.evaluate(signals)
        assertEquals(VerdictLevel.BLOCK, v.level)
        assertTrue(v.reasons.any { it.signalId.startsWith("CONVERGENCE") })
    }

    @Test
    fun `A3 native inline hook is blocked`() {
        val v = engine.evaluate(fullSignals("A3"))
        assertEquals(VerdictLevel.BLOCK, v.level)
    }

    @Test
    fun `A4 frida traces converge and block`() {
        val v = engine.evaluate(fullSignals("A4"))
        assertEquals(VerdictLevel.BLOCK, v.level)
    }

    @Test
    fun `A5 weak emulator-root signals do not hard-block alone`() {
        // 误报治理：只有弱信号、且无多通道高置信收敛，不应 BLOCK
        val v = engine.evaluate(fullSignals("A5"))
        assertTrue(v.level != VerdictLevel.BLOCK, "弱信号不应硬阻断，实际=${v.level}")
    }

    @Test
    fun `clean device is accepted end to end`() {
        val service = harness()
        val signer = service.clientSigner
        val nonce = service.issueNonce()
        val envelope = AttestationSigner(signer).sign(
            payload(nonce, amount = 5000, signals = emptyList(), counter = 1)
        )
        val decision = service.server.verify("dev-1", envelope, expectedAmountMinor = 5000)
        assertTrue(decision is ServerVerificationService.Decision.Accept)
    }

    @Test
    fun `A6 replayed nonce is rejected on second submission`() {
        val service = harness()
        val nonce = service.issueNonce()
        val envelope = AttestationSigner(service.clientSigner)
            .sign(payload(nonce, 5000, emptyList(), 1))
        val first = service.server.verify("dev-1", envelope, 5000)
        val second = service.server.verify("dev-1", envelope, 5000)
        assertTrue(first is ServerVerificationService.Decision.Accept)
        assertTrue(second is ServerVerificationService.Decision.Reject)
        assertEquals("NONCE_REPLAY", (second as ServerVerificationService.Decision.Reject).code)
    }

    @Test
    fun `A6 forged envelope without device private key is rejected`() {
        val service = harness()
        val attacker = SoftwareRsaSigner.generate("attacker")
        val nonce = service.issueNonce()
        val forged = AttestationSigner(attacker).sign(payload(nonce, 5000, emptyList(), 1))
        val decision = service.server.verify("dev-1", forged, 5000)
        assertTrue(decision is ServerVerificationService.Decision.Reject)
        assertEquals("BAD_SIGNATURE", (decision as ServerVerificationService.Decision.Reject).code)
    }

    @Test
    fun `A6 tampered amount is caught server-side even if client missed it`() {
        // 模拟攻击者改金额：证明里签的是 1 元，但服务端订单是 5000 元
        val service = harness()
        val nonce = service.issueNonce()
        val envelope = AttestationSigner(service.clientSigner)
            .sign(payload(nonce, amount = 100, signals = emptyList(), counter = 1))
        val decision = service.server.verify("dev-1", envelope, expectedAmountMinor = 5000)
        assertTrue(decision is ServerVerificationService.Decision.Reject)
        assertEquals("AMOUNT_MISMATCH", (decision as ServerVerificationService.Decision.Reject).code)
    }

    @Test
    fun `A6 counter rollback is rejected`() {
        val service = harness()
        val n1 = service.issueNonce(); val n2 = service.issueNonce()
        val sign = AttestationSigner(service.clientSigner)
        service.server.verify("dev-1", sign.sign(payload(n1, 5000, emptyList(), 10)), 5000)
        val rollback = service.server.verify("dev-1", sign.sign(payload(n2, 5000, emptyList(), 5)), 5000)
        assertTrue(rollback is ServerVerificationService.Decision.Reject)
        assertEquals("COUNTER_ROLLBACK", (rollback as ServerVerificationService.Decision.Reject).code)
    }

    @Test
    fun `attacked device attestation is rejected by server independent risk recompute`() {
        // 即便客户端谎称 verdict=CLEAN，服务端用真实信号独立复算仍判 BLOCK
        val service = harness()
        val nonce = service.issueNonce()
        val attackSignals = fullSignals("A3")
        val envelope = AttestationSigner(service.clientSigner).sign(
            payload(nonce, 5000, attackSignals, 1).copy(
                clientVerdict = com.bank.rasp.core.model.Verdict.CLEAN // 客户端撒谎
            )
        )
        val decision = service.server.verify("dev-1", envelope, 5000)
        assertTrue(decision is ServerVerificationService.Decision.Reject)
        assertContains((decision as ServerVerificationService.Decision.Reject).code, "SERVER_RISK_BLOCK")
    }

    // ---------------- 测试夹具 ----------------

    private class Harness(
        val clientSigner: SoftwareRsaSigner,
        val server: ServerVerificationService,
        private val nonceService: NonceService
    ) {
        private var n = 0
        fun issueNonce(): String = "nonce-${n++}".also { nonceService.issue(it) }
    }

    private fun harness(): Harness {
        val signer = SoftwareRsaSigner.generate("dev-1-key")
        val registry = DeviceKeyRegistry()
        registry.register("dev-1", signer.publicKey)
        var clock = 0L
        val nonceService = NonceService(ttlMs = 1_000_000, now = { clock })
        val server = ServerVerificationService(
            registry, nonceService, CounterGuard(), RiskEngine()
        )
        return Harness(signer, server, nonceService)
    }

    private fun payload(nonce: String, amount: Long, signals: List<Signal>, counter: Long) =
        AttestationPayload(
            nonce = nonce,
            transactionId = "tx-$nonce",
            amountMinor = amount,
            payeeHash = "payee-hash",
            deviceFingerprint = "test-device",
            signals = signals,
            clientVerdict = engine.evaluate(signals),
            counter = counter,
            timestampMs = now
        )
}
