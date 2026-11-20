package com.bank.rasp.demo.rasp

import android.os.Build

/**
 * 汇总设备指纹，供白名单匹配与上报。只用客观字段，不采集用户隐私。
 */
object DeviceInfo {
    val fingerprint: String = Build.FINGERPRINT ?: ""
    val brand: String = Build.BRAND ?: ""
    val model: String = Build.MODEL ?: ""
    val hardware: String = Build.HARDWARE ?: ""
    val product: String = Build.PRODUCT ?: ""
    val board: String = Build.BOARD ?: ""
    val manufacturer: String = Build.MANUFACTURER ?: ""

    /** 一行式摘要，便于日志与服务端去重。 */
    fun summary(): String =
        "$brand/$product/$hardware/$model (api=${Build.VERSION.SDK_INT}, fp=$fingerprint)"
}
