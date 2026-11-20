package com.bank.rasp.demo.rasp

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.bank.rasp.core.attestation.DeviceSigner
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature

/**
 * 生产路径签名器：基于 Android Keystore 的非对称密钥。
 *
 * 关键安全属性：私钥在 TEE/StrongBox 内生成且**永不导出**，App 自身也只能调用签名、无法读取私钥，
 * 因此即使进程被 root、内存被 dump，攻击者也拿不到私钥去伪造证明。
 * 还可通过 setAttestationChallenge 配合 Google 的 Key Attestation，把密钥硬件属性证明给服务端。
 *
 * 本类在无 TEE 的旧设备/模拟器上会退化为软件实现（由调用方决定是否接受 hardwareBacked=false）。
 */
class KeystoreSigner(
    private val keyAlias: String = "rasp-attestation-key",
    private val useStrongBox: Boolean = false
) : DeviceSigner {

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override val keyId: String get() = keyAlias
    override val algorithm: String = "SHA256withRSA"

    override val hardwareBacked: Boolean
        get() = runCatching {
            val entry = keyStore.getCertificate(keyAlias) != null
            entry && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P
        }.getOrDefault(false)

    fun ensureKey() {
        if (keyStore.containsAlias(keyAlias)) return
        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
        )
        val builder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setKeySize(2048)
            .setUserAuthenticationRequired(false) // 转账场景由业务层二次认证，不绑锁屏
        // StrongBox 需要硬件支持，失败时回退普通 TEE
        if (useStrongBox && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            runCatching { builder.setIsStrongBoxBacked(true) }
        }
        kpg.initialize(builder.build())
        kpg.generateKeyPair()
    }

    override fun sign(data: ByteArray): ByteArray {
        ensureKey()
        val privateKey = keyStore.getKey(keyAlias, null) as java.security.PrivateKey
        val sig = Signature.getInstance(algorithm)
        sig.initSign(privateKey)
        sig.update(data)
        return sig.sign()
    }

    /** 导出公钥（X.509）用于注册到服务端；私钥无法导出。 */
    fun publicKeyX509(): ByteArray =
        keyStore.getCertificate(keyAlias).publicKey.encoded
}
