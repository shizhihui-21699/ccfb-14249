package com.bank.rasp.demo.rasp

/**
 * 签名基线。生产中该值应在 CI 用正式签名证书计算后注入（建议放 native 或服务端，而非易改的 Kotlin 常量）。
 * demo 默认留空 → 重打包校验处于「未启用」提示态，避免在调试签名下持续误报，阻碍正常演示。
 */
object SignatureBaseline {
    const val expectedSha256: String = ""
}
