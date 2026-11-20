package com.bank.rasp.core.attestation

import com.bank.rasp.core.model.Channel
import com.bank.rasp.core.model.Severity
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.ThreatFamily
import com.bank.rasp.core.model.Verdict
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AttestationTest {

    private val now = 5_000_000L
    private val signer = SoftwareRsaSigner.generate("device-1-key")
    private val attestationSigner = AttestationSigner(signer)
    private val verifier = AttestationVerifier()

    private fun payload(nonce: String = "nonce-abc", amount: Long = 10000) = AttestationPayload(
        nonce = nonce,
        transactionId = "tx-1",
        amountMinor = amount,
        payeeHash = "sha256:payee",
        deviceFingerprint = "fp-1",
        signals = listOf(
            Signal("HOOK_NATIVE_INLINE::x", ThreatFamily.NATIVE_HOOK, Severity.STRONG, 0.9, "ev", Channel.NATIVE, now)
        ),
        clientVerdict = Verdict.CLEAN,
        counter = 1,
        timestampMs = now
    )

    @Test
    fun `valid envelope round-trips and verifies`() {
        val envelope = attestationSigner.sign(payload())
        val decoded = verifier.verify(envelope, signer.publicKey)
        assertNotNull(decoded)
        assertEquals("tx-1", decoded.transactionId)
        assertEquals(10000L, decoded.amountMinor)
    }

    @Test
    fun `tampered payload fails verification`() {
        // 攻击者改金额：重算 payload 但没有设备私钥，只能原样签名旧 payload，
        // 若直接篡改 envelope 里的 payload 字节，验签必失败。
        val envelope = attestationSigner.sign(payload(amount = 10000))
        val tampered = envelope.copy(
            payloadB64 = envelope.payloadB64.dropLast(2) + "AA"
        )
        assertNull(verifier.verify(tampered, signer.publicKey))
    }

    @Test
    fun `wrong public key rejects envelope`() {
        val other = SoftwareRsaSigner.generate("attacker-key")
        val envelope = attestationSigner.sign(payload())
        assertNull(verifier.verify(envelope, other.publicKey))
    }

    @Test
    fun `canonical json is stable regardless of map order`() {
        // 同一数据两次构造，canonical 文本必须一致（键排序），保证跨端验签
        val c1 = AttestationJson.canonical(payload())
        val c2 = AttestationJson.canonical(payload())
        assertEquals(c1, c2)
        assertTrue(c1.startsWith("{"))
    }

    @Test
    fun `nonce is single use and detects replay`() {
        var t = 0L
        val svc = NonceService(ttlMs = 100, now = { t })
        svc.issue("n1")
        assertEquals(NonceService.Result.Ok, svc.consume("n1"))
        assertEquals(NonceService.Result.Replayed, svc.consume("n1")) // 重放
        assertEquals(NonceService.Result.Unknown, svc.consume("never-issued")) // 伪造
    }

    @Test
    fun `nonce expires after ttl`() {
        var t = 0L
        val svc = NonceService(ttlMs = 100, now = { t })
        svc.issue("n2")
        t = 150
        assertEquals(NonceService.Result.Expired, svc.consume("n2"))
    }

    @Test
    fun `counter guard detects rollback`() {
        val guard = CounterGuard()
        assertEquals(CounterGuard.Result.Ok, guard.check("dev", 5))
        assertEquals(CounterGuard.Result.Ok, guard.check("dev", 6))
        assertEquals(CounterGuard.Result.Rollback, guard.check("dev", 4))
    }

    @Test
    fun `forged unsigned envelope cannot be accepted`() {
        // 攻击者没有私钥，自造一个信封，验签返回 null
        val fake = AttestationEnvelope(
            alg = "SHA256withRSA",
            payloadB64 = "ZmFrZQ",
            signatureB64 = "Zm9yZ2Vk",
            keyId = "device-1-key",
            hardwareBacked = false
        )
        assertNull(verifier.verify(fake, signer.publicKey))
        assertFalse(fake.hardwareBacked)
    }
}
