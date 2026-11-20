package com.bank.rasp.demo.demo

import android.content.Context
import com.bank.rasp.core.attestation.AttestationSigner
import com.bank.rasp.core.attestation.SoftwareRsaSigner
import com.bank.rasp.core.engine.CrossValidator
import com.bank.rasp.core.engine.RiskEngine
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.Verdict
import com.bank.rasp.demo.attack.AttackSimulator
import com.bank.rasp.demo.attack.AttackType
import com.bank.rasp.demo.bank.TransferRequest
import com.bank.rasp.demo.bank.TransferResult
import com.bank.rasp.demo.bank.TransferService
import com.bank.rasp.demo.rasp.DeviceInfo
import com.bank.rasp.demo.rasp.RaspCoordinator
import java.util.concurrent.atomic.AtomicLong

/**
 * 演示引擎：把探针、攻击模拟、转账保护、远程证明串成可在 UI 一键触发的流程。
 *
 * 为让示例在没有真实服务端/真机的情况下也能完整展示，这里：
 * - 设备私钥用软件 RSA（demo）；真机应换成 KeystoreSigner（已在同包提供）。
 * - 提供「只检测」与「带攻击痕迹的检测」两条路径，便于对比 verdict。
 */
class DemoEngine(context: Context) {

    private val appContext = context.applicationContext
    private val coordinator = RaspCoordinator(appContext)

    // demo 设备密钥（固定 keyId，模拟一台已注册设备）
    private val signer = SoftwareRsaSigner.generate("demo-device-key")
    private val attestationSigner = AttestationSigner(signer)
    private val counter = AtomicLong(1)

    val devicePublicKeyX509Base64: String
        get() = java.util.Base64.getEncoder().encodeToString(signer.publicKey.encoded)

    /** 一次检测的展示结果。 */
    data class DetectionOutput(
        val label: String,
        val signals: List<Signal>,
        val verdict: Verdict,
        val deviceSummary: String
    )

    /** 干净环境基线检测（只跑真实探针；模拟器上可能自然出现弱信号）。 */
    fun baselineCheck(): DetectionOutput {
        val report = coordinator.runChecks(sensitivePackage = appContext.packageName)
        return DetectionOutput("基线检测（无模拟攻击）", report.signals, report.verdict, report.deviceSummary)
    }

    /** 在真实探针结果之上叠加某类模拟攻击痕迹，再走完整裁决。 */
    fun checkUnderAttack(attack: AttackType): DetectionOutput {
        val now = System.currentTimeMillis()
        val attackSignals = AttackSimulator.emit(attack, now)
        val report = coordinator.runChecks(
            sensitivePackage = appContext.packageName,
            extraSignals = attackSignals
        )
        return DetectionOutput(attack.title, report.signals, report.verdict, report.deviceSummary)
    }

    /**
     * 模拟一次受保护转账。
     * @param attack 可选；非空时先注入该攻击痕迹
     * @param tamperAmount 若为 true，则模拟 hook 把提交金额改成与用户确认值不同
     */
    fun protectedTransfer(
        attack: AttackType?,
        tamperAmount: Boolean,
        userConfirmedAmount: Long = 5000
    ): TransferResult {
        val now = System.currentTimeMillis()
        val extra = if (attack != null) AttackSimulator.emit(attack, now) else emptyList()
        val submitAmount = if (tamperAmount) userConfirmedAmount + 999_00 else userConfirmedAmount
        val request = TransferRequest(
            transactionId = "tx-${counter.get()}",
            payeeAccountHash = "sha256:payee-demo",
            userConfirmedAmountMinor = userConfirmedAmount,
            submitAmountMinor = submitAmount
        )
        val service = TransferService(
            coordinator = coordinator,
            signer = attestationSigner,
            counterProvider = { counter.getAndIncrement() }
        )
        val nonce = "demo-nonce-${counter.get()}-${now}"
        val outcome = service.commitTransfer(
            request = request,
            serverNonce = nonce,
            secondFactorPresent = true,
            extraSignals = extra,
            expectedPackage = appContext.packageName
        )
        return when (outcome) {
            is TransferService.Outcome.Proceed -> TransferResult(
                accepted = true,
                reason = "本地通过，已生成签名证明，待服务端裁决",
                riskScore = outcome.report.verdict.score,
                blockedLocally = false
            )
            is TransferService.Outcome.Aborted -> TransferResult(
                accepted = false,
                reason = "本地 fail-closed 中止：${outcome.reasonCode}",
                riskScore = outcome.report.verdict.score,
                blockedLocally = true
            )
        }
    }

    companion object {
        fun explain(verdict: Verdict): String = buildString {
            appendLine("等级=${verdict.level} 风险分=${verdict.score}")
            appendLine("命中威胁族=${verdict.families}")
            if (verdict.reasons.isEmpty()) appendLine("（无风险信号）")
            verdict.reasons.take(6).forEach { appendLine("· ${it.signalId}: ${it.detail}") }
        }

        fun expectedChannels(): Map<String, Set<com.bank.rasp.core.model.Channel>> =
            RiskEngine.EXPECTED_CHANNELS

        fun crossValidate(signals: List<Signal>): List<Signal> =
            CrossValidator.validate(signals, RiskEngine.EXPECTED_CHANNELS, System.currentTimeMillis())

        val deviceSummary: String get() = DeviceInfo.summary()
    }
}
