# 模拟挂钩攻击与检验手册

本工程的攻击模拟器（`app/.../attack/AttackSimulator.kt`）是一套**攻击痕迹样本**：
它只在示例 App 自己的进程内，向检测管线注入「真实攻击本应留下的可观测信号」，
不包含注入其它应用、突破真实安全边界或攻击第三方的能力。
纯 Kotlin 的等价样本同时出现在 `mock-server` 的端到端测试里，可在无设备的 CI 上验证。

| 编号 | 模拟攻击 | 真实世界手法 | 预期触发信号 | 预期裁决 |
|---|---|---|---|---|
| A1 | Java 方法挂钩 | Xposed/Frida 替换转账/安全检查的 ArtMethod | `HOOK_JAVA_STACK`、`HOOK_JAVA_UNEXPECTED_FRAME`；金额被改时 `AMOUNT_MISMATCH` | BLOCK |
| A2 | 检测 API 欺骗 | Hook 检测器/读 maps 函数，让 Java 通道返回「干净」 | native/proc 仍报真实风险并多通道收敛→BLOCK；通道沉默另产生弱线索 `CROSS_CHANNEL_GAP`，内容真矛盾产生强信号 `CROSS_CHANNEL_MISMATCH` | BLOCK |
| A3 | native inline hook | Frida Interceptor 在 libc `open/read/ptrace` 序言写跳转桩 | `HOOK_NATIVE_INLINE`、`HOOK_PTR_REDIRECT`、`SELF_CRC_MISMATCH` | BLOCK |
| A4 | Frida 痕迹注入 | agent 注入后在 maps/线程名/net 端口留痕 | `INJECTION_LIB`、`FRIDA_THREAD`、`FRIDA_PORT`，多通道收敛 | BLOCK |
| A5 | 模拟器+Root 伪装 | 改 Build、su/Magisk 路径、虚拟节点、缺传感器 | `EMULATOR::*`、`ROOT_SU::*`（均 WEAK） | 不硬阻断（误报治理） |
| A6 | 远程证明伪造 | 重放旧信封/改金额/无私钥自造证明/计数器回滚 | 服务端 `BAD_SIGNATURE`/`NONCE_REPLAY`/`AMOUNT_MISMATCH`/`COUNTER_ROLLBACK` | 服务端拒绝 |

## 为什么 A2（hook 检测器本身）仍然会被抓住

攻击者 hook 了 Java 层检测函数，让它返回「无风险」。但本工程对同一事实用三条相互独立的通道采集：

1. Java API（被 hook，沉默说谎）；
2. 直接读 `/proc/self/maps`（Java File API，可能被 hook）；
3. native **裸系统调用**读同一个 `/proc`（绕过 libc，难以在用户态 hook）。

这里要区分两类强度完全不同的证据，避免误报（这是本设计的一个关键点）：

- **内容真矛盾（强证据 `CROSS_CHANNEL_MISMATCH`）**：`InjectionProbe.mapsCrossChannel()`
  比对 Java File API 与 native raw syscall 读到的**同一份 maps 的内容哈希**，两者不一致，
  说明读取通道里有人在撒谎——这才是 STRONG 篡改信号。
- **通道沉默（弱线索 `CROSS_CHANNEL_GAP`）**：某条期望通道没有报信号。探针本就可能在某通道
  查不到证据，「沉默」不等于「说谎」，因此 `CrossValidator` 只在已有高置信信号时产出一条
  WEAK、置信 0.4 的缺口提示，它**不满足**风险引擎的硬阻断阈值，不会单独误杀正常设备。

A2 真正被硬阻断，靠的是注入框架自身在 **native 与 proc 两条独立通道**上的高置信信号满足
`INJECTION_FRAMEWORK` 的多通道收敛规则（≥2 信号、≥2 通道、置信≥0.6），而不是那条弱缺口线索。
攻击者要彻底骗过，必须同时 hook Java、libc 与 raw syscall 三条路径——而 raw syscall
不经过任何可被普通 hook 的导出符号。

## 三层验证方式

### 1) 纯 JVM 单元测试（最快，CI 友好，无需设备）
```bash
./gradlew :rasp-core:test :mock-server:test
```
- `rasp-core`：风险引擎、交叉验证、白名单、签名/验签、nonce、计数器。
- `mock-server`：六类攻击的端到端裁决、重放/篡改/伪造/回滚拒绝。

### 2) native 扫描器主机自检（验证 C++ 平台无关逻辑）
```bash
cd app/src/main/cpp
clang++ -std=c++17 host_test.cpp scanners.cpp raw_syscall.cpp -o /tmp/rasp_host_test && /tmp/rasp_host_test
```

### 3) Android 真机/模拟器（验证 JNI 与真实 /proc 采集）
```bash
./gradlew :app:assembleDebug
# 安装后在界面上点「基线检测」「A1~A5」「受保护转账」
```
> 模拟器上「基线检测」可能自然出现模拟器弱信号（EMULATOR::*），这正是预期：
> 它们是 WEAK 信号，单独不会 BLOCK，可观察到误报治理与多信号收敛的区别。

### 4) 模拟服务端联调
```bash
./gradlew :mock-server:run   # 监听 :8080
# /nonce 下发挑战；/transfer 验签、防重放、独立复算裁决
```

## 自己扩展一个攻击 / 一个探针
- 加攻击：在 `AttackType` 增加枚举，在 `AttackSimulator.emit` 增加对应信号样本，
  并在 `EndToEndAdversaryTest` 增加断言。
- 加探针：实现一个返回 `List<Signal>` 的探针，挂到 `RaspCoordinator.runChecks`；
  native 特征加到 `scanners.cpp`；阈值/权重只改 `RiskPolicy`，无需动检测代码。
