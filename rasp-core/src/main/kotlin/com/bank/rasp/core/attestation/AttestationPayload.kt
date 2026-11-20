package com.bank.rasp.core.attestation

import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.Verdict
import kotlinx.serialization.Serializable

/**
 * 远程证明载荷。客户端在每次敏感操作（如转账）时，用服务端下发的一次性 nonce 组装，
 * 并由设备私钥签名。服务端凭签名确认「这确实来自持有对应密钥的设备、内容未被篡改」，
 * 凭 nonce 确认「不是旧证明的重放」。
 */
@Serializable
data class AttestationPayload(
    /** 服务端本次挑战下发的一次性随机数。 */
    val nonce: String,
    /** 业务会话 / 转账请求 id，把证明与具体交易绑定，防止张冠李戴。 */
    val transactionId: String,
    /** 转账金额（最小货币单位），纳入签名，使「篡改金额」无法绕开服务端比对。 */
    val amountMinor: Long,
    val payeeHash: String,
    val deviceFingerprint: String,
    /** 本次采集到的全部信号（含证据），服务端独立复算风险。 */
    val signals: List<Signal>,
    /** 客户端本地裁决，供服务端对照（服务端不信它，只信自己复算的结果）。 */
    val clientVerdict: Verdict,
    /** 单调递增的设备计数器，辅助检测重放/回滚。 */
    val counter: Long,
    val timestampMs: Long
)

/**
 * 签名后的证明信封。alg 标识签名算法；demo 用软件 RSA/EC，
 * 生产路径切到 Android Keystore 硬件密钥（私钥不可导出）。
 */
@Serializable
data class AttestationEnvelope(
    val alg: String,
    /** base64url(canonical JSON payload)。 */
    val payloadB64: String,
    /** base64url(signature over payloadB64)。 */
    val signatureB64: String,
    /** 对应公钥的标识，服务端据此查找注册公钥。 */
    val keyId: String,
    /** 是否为硬件支持密钥（Keystore TEE/StrongBox）。demo 恒 false。 */
    val hardwareBacked: Boolean
)
