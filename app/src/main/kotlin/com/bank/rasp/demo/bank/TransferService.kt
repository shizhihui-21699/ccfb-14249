package com.bank.rasp.demo.bank

import com.bank.rasp.core.attestation.AttestationEnvelope
import com.bank.rasp.core.attestation.AttestationPayload
import com.bank.rasp.core.attestation.AttestationSigner
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.Verdict
import com.bank.rasp.core.model.VerdictLevel
import com.bank.rasp.demo.rasp.RaspCoordinator
import com.bank.rasp.demo.rasp.RaspReport

/**
 * 转账服务：演示「确认被攻击时安全中止敏感操作」。
 *
 * 防御链（任意一环不过即 fail-closed 中止，且不向前端暴露具体触发项，避免给攻击者反馈）：
 *  1. RASP 运行时检测 → verdict 达 BLOCK 直接中止；
 *  2. 金额完整性：用户确认金额 == 提交金额，不一致即中止（对抗篡改金额）；
 *  3. 本地安全检查（限额/二次认证）；
 *  4. 组装远程证明 payload（含金额、全量信号、nonce、计数器）并签名；
 *  5. 服务端独立验签 + 验重放 + 复算风险后最终裁决（客户端结论不被信任）。
 *
 * 注意：这里不直接 System.exit/杀进程——只拒绝本次敏感操作，只读功能仍可用，降低误伤面。
 */
class TransferService(
    private val coordinator: RaspCoordinator,
    private val signer: AttestationSigner,
    /** 设备本地单调计数器（生产放 EncryptedSharedPreferences/Keystore）。 */
    private val counterProvider: () -> Long,
    private val nowMs: () -> Long = { System.currentTimeMillis() }
) {

    sealed class Outcome {
        /** 本地通过，已生成待服务端裁决的证明信封。 */
        data class Proceed(val envelope: AttestationEnvelope, val report: RaspReport) : Outcome()
        /** 本地 fail-closed 中止。reasonCode 刻意中性，不含具体检测细节。 */
        data class Aborted(val reasonCode: String, val report: RaspReport) : Outcome()
    }

    fun commitTransfer(
        request: TransferRequest,
        serverNonce: String,
        secondFactorPresent: Boolean,
        sensitiveMethods: List<java.lang.reflect.Method> = emptyList(),
        extraSignals: List<Signal> = emptyList(),
        expectedPackage: String
    ): Outcome {
        // ---- 第 1 环：运行时检测 ----
        val report = coordinator.runChecks(
            sensitiveMethods = sensitiveMethods,
            sensitivePackage = expectedPackage,
            extraSignals = extraSignals
        )
        if (report.verdict.shouldBlockSensitive) {
            return Outcome.Aborted(neutralReason(report.verdict.level), report)
        }

        // ---- 第 2 环：金额完整性（对抗 hook 改金额）----
        if (!request.amountIntact) {
            return Outcome.Aborted("AMOUNT_MISMATCH", report)
        }

        // ---- 第 3 环：本地安全检查 ----
        val limit = LocalSecurityChecks.checkDailyLimit(request.submitAmountMinor)
        val factor = LocalSecurityChecks.checkSecondFactor(request.submitAmountMinor, secondFactorPresent)
        if (!limit.passed || !factor.passed) {
            return Outcome.Aborted("LOCAL_CHECK_FAILED", report)
        }

        // ---- 第 4 环：组装并签名远程证明（金额与信号都纳入签名，无法事后篡改）----
        val payload = AttestationPayload(
            nonce = serverNonce,
            transactionId = request.transactionId,
            amountMinor = request.submitAmountMinor,
            payeeHash = request.payeeAccountHash,
            deviceFingerprint = report.deviceSummary,
            signals = report.signals,
            clientVerdict = report.verdict,
            counter = counterProvider(),
            timestampMs = nowMs()
        )
        val envelope = signer.sign(payload)

        // HIGH 但未到 BLOCK：不本地硬阻断，把完整证据交给服务端裁决（灰度/降误报）
        return Outcome.Proceed(envelope, report)
    }

    /** 中性错误码：告诉用户「操作无法完成」，但不泄露是哪条检测触发，防止攻击者据此调参。 */
    private fun neutralReason(level: VerdictLevel): String =
        if (level == VerdictLevel.BLOCK) "ENVIRONMENT_UNSAFE" else "RISK_REVIEW"
}
