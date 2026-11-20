package com.bank.rasp.demo.rasp

import android.content.Context
import android.content.pm.PackageManager
import com.bank.rasp.core.model.Channel
import com.bank.rasp.core.model.Severity
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.ThreatFamily

/**
 * L4 反篡改 / 自校验层。
 *
 * 两条机制：
 * 1) native 函数体 CRC 基线：so 加载后尽早建立基线（[establishBaselines]），
 *    之后定期/敏感操作前重算比对。函数被 inline patch 时 CRC 必然变化。
 *    基线存在 App 内存（生产可结合 Keystore 加密落盘），不硬编码在 so 内，避免被一并 patch。
 * 2) APK 签名基线：运行时签名哈希与编译期内置基线比对，重打包植入框架时签名必然改变。
 */
class NativeSelfCheck(private val appContext: Context) {

    // 要监控的 libc 符号 + 读取长度（demo 固定，生产按符号实际大小/序言长度）
    private val watchedSymbols = listOf("open", "openat", "read", "ptrace", "strcmp")
    private val crcLength = 64

    // 符号 -> 基线 CRC。首次建立后不再更改。
    private val baselines = HashMap<String, Int>()
    private var baselineReady = false

    private val nowMs get() = System.currentTimeMillis()

    /** 应在 Application 最早阶段、任何第三方 SDK 初始化之前调用。 */
    fun establishBaselines() {
        if (!NativeBridge.isAvailable || baselineReady) return
        for (sym in watchedSymbols) {
            val crc = NativeBridge.nativeCrcOfSymbol(sym, crcLength)
            if (crc >= 0) baselines[sym] = crc
        }
        baselineReady = baselines.isNotEmpty()
    }

    fun verify(): List<Signal> = buildList {
        if (!NativeBridge.isAvailable) return@buildList
        if (!baselineReady) {
            add(Signal("SELF_BASELINE_MISSING", ThreatFamily.TAMPERED_DETECTOR, Severity.WEAK,
                0.5, "native 自校验基线未建立", Channel.NATIVE, nowMs))
            return@buildList
        }
        for (sym in watchedSymbols) {
            val baseline = baselines[sym] ?: continue
            val current = NativeBridge.nativeCrcOfSymbol(sym, crcLength)
            if (current >= 0 && current != baseline) {
                add(Signal(
                    "SELF_CRC_MISMATCH::$sym", ThreatFamily.TAMPERED_DETECTOR,
                    Severity.CRITICAL, 0.95,
                    "libc 函数 $sym 函数体 CRC 变化（基线=$baseline 当前=$current），疑似被 inline patch",
                    Channel.RAW_SYSCALL, nowMs
                ))
            }
        }
    }

    /**
     * 重打包检测：取当前签名 SHA-256，与编译期注入的基线比较。
     * demo 把基线放在 BuildConfig 之外的资源占位（见 [SignatureBaseline]），生产应放到 native/服务端。
     */
    fun verifySignature(): List<Signal> = buildList {
        val expected = SignatureBaseline.expectedSha256
        if (expected.isBlank()) {
            // 未配置基线（演示环境）→ 不报攻击，但提示未启用
            add(Signal("SIG_BASELINE_UNCONFIGURED", ThreatFamily.REPACKAGING, Severity.INFO,
                0.1, "未配置签名基线，跳过重打包校验（演示态）", Channel.STATIC_BASELINE, nowMs))
            return@buildList
        }
        val actual = currentSignatureSha256()
        if (actual != null && !actual.equals(expected, ignoreCase = true)) {
            add(Signal(
                "SIGNATURE_MISMATCH", ThreatFamily.REPACKAGING, Severity.CRITICAL, 0.95,
                "APK 签名与内置基线不一致，疑似重打包", Channel.STATIC_BASELINE, nowMs
            ))
        }
    }

    private fun currentSignatureSha256(): String? = runCatching {
        val pm = appContext.packageManager
        val pkg = appContext.packageName
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            val sig = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                .signingInfo?.apkContentsSigners?.firstOrNull()
            sig?.let { sha256(it.toByteArray()) }
        } else {
            @Suppress("DEPRECATION")
            val sig = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures?.firstOrNull()
            sig?.let { sha256(it.toByteArray()) }
        }
    }.getOrNull()

    private fun sha256(bytes: ByteArray): String {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        return md.digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
