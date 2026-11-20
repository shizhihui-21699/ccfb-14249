package com.bank.rasp.core.attestation

import kotlinx.serialization.json.Json
import java.security.KeyPair
import java.security.PublicKey
import java.security.Signature
import java.util.Base64

/**
 * 统一的规范化 JSON：排序键、无多余空白，保证客户端与服务端对同一载荷算出完全一致的字节，
 * 否则跨平台/跨库验签会因为字段顺序不同而失败。
 */
object AttestationJson {
    val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    /** 先序列化为树，再递归排序键，输出 canonical 文本。 */
    fun canonical(payload: AttestationPayload): String {
        val tree = json.encodeToJsonElement(AttestationPayload.serializer(), payload)
        return canonicalElement(tree)
    }

    private fun canonicalElement(element: kotlinx.serialization.json.JsonElement): String =
        when (element) {
            is kotlinx.serialization.json.JsonObject ->
                element.entries.sortedBy { it.key }
                    .joinToString(",", "{", "}") { (k, v) ->
                        "\"$k\":${canonicalElement(v)}"
                    }
            is kotlinx.serialization.json.JsonArray ->
                element.joinToString(",", "[", "]") { canonicalElement(it) }
            is kotlinx.serialization.json.JsonPrimitive ->
                if (element.isString) "\"${element.content}\"" else element.content
            else -> "null"
        }
}

/** 设备签名器抽象。生产环境用 Keystore 实现替换软件实现。 */
interface DeviceSigner {
    val keyId: String
    val algorithm: String       // 例如 SHA256withRSA
    val hardwareBacked: Boolean
    fun sign(data: ByteArray): ByteArray
}

/** 验签器抽象，服务端持有注册公钥。 */
interface SignatureVerifier {
    fun verify(publicKey: PublicKey, data: ByteArray, signature: ByteArray): Boolean
}

/**
 * 演示用软件 RSA 签名器。⚠️ 私钥存在进程内存/普通存储，root 高手可提取，
 * 仅用于无硬件环境的端到端演示。生产必须改用 Android Keystore（见 app 模块 KeystoreSigner）。
 */
class SoftwareRsaSigner(
    private val keyPair: KeyPair,
    override val keyId: String
) : DeviceSigner {

    override val algorithm = "SHA256withRSA"
    override val hardwareBacked = false

    val publicKey: PublicKey get() = keyPair.public

    override fun sign(data: ByteArray): ByteArray {
        val sig = Signature.getInstance(algorithm)
        sig.initSign(keyPair.private)
        sig.update(data)
        return sig.sign()
    }

    companion object {
        fun generate(keyId: String): SoftwareRsaSigner {
            val kpg = java.security.KeyPairGenerator.getInstance("RSA")
            kpg.initialize(2048)
            return SoftwareRsaSigner(kpg.generateKeyPair(), keyId)
        }
    }
}

/** JCA 标准验签，App 与 mock-server 共用。 */
class JcaSignatureVerifier(private val algorithm: String = "SHA256withRSA") : SignatureVerifier {
    override fun verify(publicKey: PublicKey, data: ByteArray, signature: ByteArray): Boolean =
        try {
            val sig = Signature.getInstance(algorithm)
            sig.initVerify(publicKey)
            sig.update(data)
            sig.verify(signature)
        } catch (t: Throwable) {
            false
        }
}

/** 组装并签名证明信封。 */
class AttestationSigner(private val signer: DeviceSigner) {

    fun sign(payload: AttestationPayload): AttestationEnvelope {
        val canonical = AttestationJson.canonical(payload)
        val signature = signer.sign(canonical.toByteArray(Charsets.UTF_8))
        val enc = Base64.getUrlEncoder().withoutPadding()
        return AttestationEnvelope(
            alg = signer.algorithm,
            payloadB64 = enc.encodeToString(canonical.toByteArray(Charsets.UTF_8)),
            signatureB64 = enc.encodeToString(signature),
            keyId = signer.keyId,
            hardwareBacked = signer.hardwareBacked
        )
    }
}

/** 验签并还原载荷；验签失败返回 null（调用方应按攻击处理）。 */
class AttestationVerifier(private val verifier: SignatureVerifier = JcaSignatureVerifier()) {

    private val dec = Base64.getUrlDecoder()

    fun verify(envelope: AttestationEnvelope, publicKey: PublicKey): AttestationPayload? {
        return try {
            val payloadBytes = dec.decode(envelope.payloadB64)
            val signatureBytes = dec.decode(envelope.signatureB64)
            val ok = verifier.verify(publicKey, payloadBytes, signatureBytes)
            if (!ok) return null
            val canonical = String(payloadBytes, Charsets.UTF_8)
            AttestationJson.json.decodeFromString(AttestationPayload.serializer(), canonical)
        } catch (t: Throwable) {
            null
        }
    }
}
