package com.bank.rasp.demo.bank

/**
 * 本地安全检查（限额、二次认证开关等）。攻击者常 hook 这类检查让其恒返回 true 以跳过风控。
 *
 * 因此：
 * - 检查结果不只返回布尔，而是返回带「检查依据」的结构化结果，供转账服务复核；
 * - 关键判定同时由服务端再做一遍（客户端检查不可信，只是第一道门）。
 */
object LocalSecurityChecks {

    const val DAILY_LIMIT_MINOR = 50_000_00L // 单日限额 50 万（分）= 5000 元

    data class CheckResult(
        val passed: Boolean,
        val checkName: String,
        val detail: String
    )

    fun checkDailyLimit(amountMinor: Long): CheckResult =
        if (amountMinor in 1..DAILY_LIMIT_MINOR)
            CheckResult(true, "DAILY_LIMIT", "金额 $amountMinor 在限额内")
        else
            CheckResult(false, "DAILY_LIMIT", "金额 $amountMinor 超出限额或非法")

    fun checkSecondFactor(amountMinor: Long, secondFactorPresent: Boolean): CheckResult {
        val required = amountMinor >= 10_000_00L // 1 万元以上需二次认证
        val passed = !required || secondFactorPresent
        return CheckResult(passed, "SECOND_FACTOR",
            if (required) "大额需二次认证，present=$secondFactorPresent" else "小额免二次认证")
    }
}
