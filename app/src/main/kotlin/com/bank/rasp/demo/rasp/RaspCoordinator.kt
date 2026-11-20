package com.bank.rasp.demo.rasp

import android.content.Context
import com.bank.rasp.core.engine.CrossValidator
import com.bank.rasp.core.engine.RiskEngine
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.Verdict
import com.bank.rasp.core.policy.AllowlistEntry
import com.bank.rasp.core.policy.FalsePositiveMitigator
import com.bank.rasp.core.policy.RiskPolicy
import java.lang.reflect.Method

/**
 * RASP 编排器：按 L1→L4 顺序调度探针，应用白名单与交叉验证，交给风险引擎裁决。
 *
 * 它只产出 [RaspReport]，不直接杀进程——是否中止敏感操作由业务层（TransferService）
 * 根据 [Verdict.shouldBlockSensitive] 决定，做到「检测与响应解耦」，便于灰度和测试。
 */
class RaspCoordinator(
    appContext: Context,
    private val policy: RiskPolicy = RiskPolicy(),
    allowlist: List<AllowlistEntry> = DEFAULT_ALLOWLIST
) {
    private val app = appContext.applicationContext
    private val environment = EnvironmentProbe(app)
    private val injection = InjectionProbe()
    private val javaHook = JavaHookProbe()
    private val selfCheck = NativeSelfCheck(app)
    private val mitigator = FalsePositiveMitigator(allowlist)
    private val engine = RiskEngine(policy)

    init {
        // 越早建立 native CRC 基线越好（在攻击者有机会注入之前）
        selfCheck.establishBaselines()
    }

    /**
     * 运行一次完整检测。
     * @param sensitiveMethods 业务关键 Java 方法（转账提交、安全检查），用于 hook 检测
     * @param sensitivePackage 当前敏感操作所在包，用于调用栈完整性校验
     * @param extraSignals 攻击模拟器注入的痕迹（仅演示/自测用），会与真实探针信号合并后统一裁决
     */
    fun runChecks(
        sensitiveMethods: List<Method> = emptyList(),
        sensitivePackage: String? = null,
        extraSignals: List<Signal> = emptyList()
    ): RaspReport {
        val now = System.currentTimeMillis()
        val signals = ArrayList<Signal>()

        // L1 环境
        signals += environment.run()
        // L2 注入框架（含 native maps/线程/端口 + Java Xposed + maps 双通道）
        signals += injection.run()
        // L3 Java hook（栈完整性）
        if (sensitivePackage != null) signals += javaHook.checkCallStack(sensitivePackage)
        // L4 自校验 + 重打包
        signals += selfCheck.verify()
        signals += selfCheck.verifySignature()
        // 演示用：合并模拟攻击痕迹
        signals += extraSignals

        // 多通道交叉验证：高置信事实组若有期望通道沉默，补一条弱「通道缺口」线索（不单独阻断）
        signals += CrossValidator.validate(signals, RiskEngine.EXPECTED_CHANNELS, now)

        // 误报治理：白名单只降权不删除
        val mitigated = mitigator.apply(DeviceInfo.fingerprint, signals)

        val verdict = engine.evaluate(mitigated)
        return RaspReport(mitigated, verdict, DeviceInfo.summary())
    }

    companion object {
        // 示例白名单：演示如何为已知机型的良性特征降权（实际应由服务端策略下发）
        val DEFAULT_ALLOWLIST: List<AllowlistEntry> = listOf(
            // 例：某定制 ROM 机型无陀螺仪属正常，把该弱信号压到 0.15
            AllowlistEntry("vendor-demo-rom", "EMU_SENSOR_MISSING", 0.15, "该机型硬件无陀螺仪")
        )
    }
}

/** 一次检测的完整结果。 */
data class RaspReport(
    val signals: List<Signal>,
    val verdict: Verdict,
    val deviceSummary: String
) {
    val isUnderAttack: Boolean get() = verdict.shouldBlockSensitive
}
