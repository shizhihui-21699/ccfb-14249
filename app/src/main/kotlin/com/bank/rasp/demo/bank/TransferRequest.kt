package com.bank.rasp.demo.bank

/**
 * 转账请求。金额用最小货币单位（分）的 Long，避免浮点篡改/精度问题。
 */
data class TransferRequest(
    val transactionId: String,
    val payeeAccountHash: String,
    /** 用户在 UI 上确认的金额（分）。 */
    val userConfirmedAmountMinor: Long,
    /** 即将提交给服务端的金额（分）。正常应与用户确认值一致；被 hook 篡改时会不同。 */
    val submitAmountMinor: Long,
    val memo: String = ""
) {
    /** 金额一致性：用户确认值 == 实际提交值。 */
    val amountIntact: Boolean get() = userConfirmedAmountMinor == submitAmountMinor
}

/** 转账结果。 */
data class TransferResult(
    val accepted: Boolean,
    val reason: String,
    val riskScore: Int,
    val blockedLocally: Boolean
)
