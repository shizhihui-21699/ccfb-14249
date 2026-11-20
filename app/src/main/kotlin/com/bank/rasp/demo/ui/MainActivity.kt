package com.bank.rasp.demo.ui

import android.os.Bundle
import android.view.ViewGroup
import androidx.appcompat.app.AppCompatActivity
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.Verdict
import com.bank.rasp.demo.attack.AttackType
import com.bank.rasp.demo.demo.DemoEngine
import com.bank.rasp.demo.databinding.ActivityMainBinding
import com.google.android.material.button.MaterialButton
import com.google.android.material.snackbar.Snackbar

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var engine: DemoEngine

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        engine = DemoEngine(this)
        binding.deviceInfo.text = "设备: ${DemoEngine.deviceSummary}\n公钥已生成（demo 软件密钥，生产用 Keystore 硬件密钥）"

        binding.btnBaseline.setOnClickListener { show(engine.baselineCheck().let { render(it.label, it.signals, it.verdict) }) }

        // 动态生成六个攻击按钮
        AttackType.values().forEach { attack ->
            val btn = MaterialButton(this).apply {
                text = attack.title
                layoutParams = ViewGroup.MarginLayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).also { it.topMargin = 12 }
                setOnClickListener {
                    val out = engine.checkUnderAttack(attack)
                    show(render(out.label, out.signals, out.verdict) + explainAttack(attack))
                }
            }
            binding.attackButtons.addView(btn)
        }

        binding.btnTransferClean.setOnClickListener {
            val result = engine.protectedTransfer(attack = null, tamperAmount = binding.swTamper.isChecked)
            show(renderTransfer(result))
        }

        binding.btnTransferAttack.setOnClickListener {
            val result = engine.protectedTransfer(
                attack = AttackType.A1_JAVA_HOOK,
                tamperAmount = binding.swTamper.isChecked
            )
            show(renderTransfer(result))
        }
    }

    private fun render(label: String, signals: List<Signal>, verdict: Verdict): String = buildString {
        appendLine("==== $label ====")
        appendLine(DemoEngine.explain(verdict))
        appendLine("信号明细（${signals.size} 条，按通道着色在服务端研判）：")
        signals
            .sortedWith(compareByDescending<Signal> { it.severity.ordinal }.thenByDescending { it.confidence })
            .take(20)
            .forEach { s ->
                appendLine("· [${s.severity}] ${s.id}")
                appendLine("    通道=${s.channel} 置信=${s.confidence} 族=${s.family}")
                appendLine("    证据=${s.evidence}")
            }
        if (verdict.shouldBlockSensitive) {
            appendLine("\n>>> 裁决 BLOCK：敏感操作将被本地 fail-closed 中止")
        } else {
            appendLine("\n>>> 裁决 ${verdict.level}：未触发硬阻断（HIGH 会交服务端裁决）")
        }
    }

    private fun explainAttack(a: AttackType): String = buildString {
        appendLine("\n— 攻击说明 —")
        appendLine("真实手法: ${a.realWorldTechnique}")
        appendLine("预期检测: ${a.expectedDetection}")
    }

    private fun renderTransfer(result: com.bank.rasp.demo.bank.TransferResult): String = buildString {
        appendLine("==== 受保护转账 ====")
        appendLine("结果: ${if (result.accepted) "放行（待服务端裁决）" else "已中止"}")
        appendLine("原因: ${result.reason}")
        appendLine("本地风险分: ${result.riskScore} / 100")
        appendLine("本地硬阻断: ${result.blockedLocally}")
        appendLine("提示: 即使本地放行，服务端仍会验签 + 防重放 + 独立复算后最终裁决")
    }

    private fun show(text: String) {
        binding.output.text = text
        Snackbar.make(binding.root, "检测完成", Snackbar.LENGTH_SHORT).show()
    }
}
