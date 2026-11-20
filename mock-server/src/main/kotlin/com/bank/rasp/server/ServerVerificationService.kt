package com.bank.rasp.server

import com.bank.rasp.core.attestation.AttestationEnvelope
import com.bank.rasp.core.attestation.AttestationPayload
import com.bank.rasp.core.attestation.AttestationVerifier
import com.bank.rasp.core.attestation.CounterGuard
import com.bank.rasp.core.attestation.NonceService
import com.bank.rasp.core.engine.RiskEngine
import com.bank.rasp.core.model.Verdict
import com.bank.rasp.core.model.VerdictLevel
import java.security.PublicKey
import java.util.Base64

/**
 * 服务端裁决服务：演示「检测结果让服务端知道且不被伪造」。
 *
 * 服务端不信任客户端传来的 clientVerdict，而是：
 *  1. 用注册公钥验签 → 确认证明来自持有设备私钥的真实 App、内容未篡改；
 *  2. 校验 nonce 一次性、未过期 → 防重放；
 *  3. 校验 counter 单调 → 防回滚/克隆；
 *  4. 用自己的 RiskEngine 独立复算信号 → 自主裁决；
 *  5. 金额与服务端订单比对（由路由层传入订单金额）。
 */
class ServerVerificationService(
    private val keyRegistry: DeviceKeyRegistry,
    private val nonces: NonceService,
    private val counters: CounterGuard = CounterGuard(),
    private val engine: RiskEngine = RiskEngine(),
    private val verifier: AttestationVerifier = AttestationVerifier()
) {

    sealed class Decision {
        data class Accept(val reason: String, val serverVerdict: Verdict) : Decision()
        data class Reject(val code: String, val reason: String) : Decision()
    }

    fun verify(
        deviceId: String,
        envelope: AttestationEnvelope,
        expectedAmountMinor: Long?
    ): Decision {
        // 1) 取注册公钥；未注册设备直接拒绝
        val publicKey = keyRegistry.publicKeyOf(deviceId)
            ?: return Decision.Reject("UNKNOWN_DEVICE", "设备未注册，无公钥可验签")

        // 2) 验签并还原载荷
        val payload: AttestationPayload = verifier.verify(envelope, publicKey)
            ?: return Decision.Reject("BAD_SIGNATURE", "证明验签失败：伪造或被篡改")

        // 3) nonce 防重放（一次性消费）
        when (val r = nonces.consume(payload.nonce)) {
            NonceService.Result.Ok -> Unit
            NonceService.Result.Replayed ->
                return Decision.Reject("NONCE_REPLAY", "nonce 已被使用，重放攻击")
            NonceService.Result.Unknown ->
                return Decision.Reject("NONCE_UNKNOWN", "nonce 非本服务端签发")
            NonceService.Result.Expired ->
                return Decision.Reject("NONCE_EXPIRED", "nonce 已过期")
        }

        // 4) counter 防回滚
        if (counters.check(deviceId, payload.counter) is CounterGuard.Result.Rollback) {
            return Decision.Reject("COUNTER_ROLLBACK", "设备计数器回滚，疑似克隆/回滚")
        }

        // 5) 金额与服务端订单比对（防 hook 改金额；即使本地没拦住，服务端也拦）
        if (expectedAmountMinor != null && payload.amountMinor != expectedAmountMinor) {
            return Decision.Reject("AMOUNT_MISMATCH",
                "证明金额 ${payload.amountMinor} 与订单金额 $expectedAmountMinor 不符")
        }

        // 6) 服务端独立复算风险（不信客户端 verdict）
        val serverVerdict = engine.evaluate(payload.signals)
        return if (serverVerdict.level == VerdictLevel.BLOCK) {
            Decision.Reject("SERVER_RISK_BLOCK",
                "服务端复算风险达 BLOCK：${serverVerdict.reasons.joinToString { it.signalId }}")
        } else {
            Decision.Accept("验签通过且风险可接受（服务端等级=${serverVerdict.level}）", serverVerdict)
        }
    }
}

/** 设备注册公钥库（demo 用内存 Map；生产接 KMS/数据库，公钥经注册流程带外校验）。 */
class DeviceKeyRegistry {
    private val keys = HashMap<String, PublicKey>()

    fun register(deviceId: String, publicKey: PublicKey) {
        keys[deviceId] = publicKey
    }

    fun publicKeyOf(deviceId: String): PublicKey? = keys[deviceId]

    /** 便于测试：从 X.509 SubjectPublicKeyInfo Base64 注册公钥。 */
    fun registerX509Base64(deviceId: String, b64: String) {
        val bytes = Base64.getDecoder().decode(b64)
        val key = java.security.KeyFactory.getInstance("RSA")
            .generatePublic(java.security.spec.X509EncodedKeySpec(bytes))
        keys[deviceId] = key
    }
}
