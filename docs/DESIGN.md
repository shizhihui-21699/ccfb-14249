# 手机银行运行时自我保护（RASP）示例工程

> 目标：在用户不知情、且注入工具会主动隐藏自身的前提下，让应用发现**进程被注入、关键函数被挂钩、运行在被篡改系统 / 模拟器上**，
> 并在**确认被攻击时安全中止敏感操作（转账等）**；检测结论要能让服务端验证、且无法被伪造。
>
> 这是一套用于教学、红蓝对抗演练和方案评审的**示例实现**，不是可直接投产的商业级加固。文末「能力边界」明确说明它防不住什么。

---

## 1. 威胁模型

### 1.1 对手能力假设
攻击者对设备具备逐步增强的控制权，示例按能力从低到高覆盖：

| 级别 | 能力 | 典型工具 / 手法 |
|---|---|---|
| L1 | 在用户手机上装恶意 App，诱导开启「未知来源 / 辅助功能」 | 仿冒输入、界面覆盖（tapjacking） |
| L2 | Root / Magisk 环境，可读 `/proc`、注入 so | LSPosed/Xposed、Zygisk 模块 |
| L3 | 动态插桩，运行时改 Java 方法与 native 函数 | Frida（Gadget / Server）、ptrace 注入 |
| L4 | 主动反检测：挂钩检测 API 让其返回「干净」结果 | Frida 反检测脚本、Magisk Hide / Shamiko、Hook 本工程的检测函数 |
| L5 | 模拟器 / 定制 ROM，可改系统属性、伪造 build 信息 | 改 `ro.kernel.qemu`、伪造 `/proc/cpuinfo`、重打包 |

### 1.2 我们要保护的资产
1. **转账金额 / 收款账户**在「用户确认 → 提交服务端」之间不被改写。
2. **本地安全检查**（限额、二次认证开关、风控前置校验）不被跳过。
3. 设备的**真实风险状态**能可信地上报到服务端，而不是被攻击者改成「一切正常」。

### 1.3 设计原则（对应你提的四个难点）
- **难点：工具会隐藏自己** → 不依赖单一 API，采用**多源交叉验证（cross-validation）**，任何一个数据源能被单独伪造，但让多个相互独立的通道同时说谎的成本高得多。注意区分「同一工件内容真矛盾」（强信号）与「某通道沉默」（仅弱线索，防误报），见 L4。
- **难点：检测代码本身会被挂钩改返回值** → ① 关键探针下沉到 **native + 裸系统调用（raw syscall）**，绕过被 hook 的 libc；② **自校验**：检测函数之间互相做完整性 / 返回值一致性检查，检测「检测器是否被改」。
- **难点：厂商定制 / 老机型误报** → **风险信号（signal）与判定（verdict）分离**；单个弱信号永不阻断；带置信度、可被服务端策略灰度；维护已知良性特征白名单；阻断前要求「多信号收敛」。
- **难点：结论要让服务端知道且不被伪造** → 设备私钥做**挑战 - 应答式远程证明（attestation）**，服务端持有 nonce 防重放、验签防伪造；**最终放行/拒绝由服务端裁决**，客户端只负责如实采集和本地「失败即关闭（fail-closed）」。

---

## 2. 检测分层架构

分五层，自底向上。**越底层越难被用户态 hook 篡改，越上层越贴近业务语义。** 每层产出结构化 `Signal`，统一汇入风险引擎。

```
┌──────────────────────────────────────────────────────────────┐
│ L5  响应与远程证明层  RiskEngine 裁决 + Attestation 签名上报    │
│        本地 fail-closed 中止敏感操作；服务端 nonce 挑战验签裁决   │
├──────────────────────────────────────────────────────────────┤
│ L4  反篡改 / 自校验层  探针交叉验证、native 函数指针 canary、     │
│        Java ArtMethod 完整性、检测返回值一致性、重打包签名校验     │
├──────────────────────────────────────────────────────────────┤
│ L3  函数挂钩检测层    Java 方法 hook、native inline/GOT hook、   │
│        调用栈异常、敏感转账函数运行时完整性                        │
├──────────────────────────────────────────────────────────────┤
│ L2  注入 / hook 框架检测  Frida/Xposed/LSPosed、可疑 so、         │
│        端口/线程名/内存映射、ptrace 跟踪、gum/gadget 痕迹         │
├──────────────────────────────────────────────────────────────┤
│ L1  环境层            模拟器、root/ Magisk、调试器、              │
│        未知来源、系统篡改（build 属性与硬件交叉验证）               │
└──────────────────────────────────────────────────────────────┘
        每个探针：Probe → List<Signal>(id, 置信度, 证据, 通道)
```

### L1 环境层（Environment）
- **模拟器**：`Build.HARDWARE/MODEL/PRODUCT` 等属性与传感器、CPU 特征、内核文件、虚拟化驱动（`/dev/qemu_pipe`、`goldfish`、`ranchu`、`vbox`、`generic`）交叉验证；只命中一个属性不报警。
- **Root / Magisk**：`su` 路径、`which su`、Magisk 挂载点、`/sbin/.magisk`、可疑可写分区、root 管理 App 包名；注意 Magisk Hide 会隐藏这些，所以这里只作为弱信号，需与 L2/L4 信号收敛。
- **调试器 / 篡改系统**：`Debug.isDebuggerConnected`（易被 hook，弱信号）+ native `ptrace` 自检 + 系统属性与实际硬件不一致。

### L2 注入 / Hook 框架检测（Injection）
- **Frida**：
  - 线程名扫描（`gmain`、`gum-js-loop`、`pool-frida`）——直接读 `/proc/self/task/*/comm`，不走可能被 hook 的 API；
  - 内存映射扫描 `/proc/self/maps`，找 `frida-agent`、`frida-gadget`、`libfrida`、`linjector`；
  - 默认 D-Bus 端口 27042/27043 的连接（`/proc/self/net/tcp`）；
  - `re.frida.server` 命名端口。
- **Xposed / LSPosed**：调用栈里出现 `de.robv.android.xposed`、`org.lsposed`；已加载的 class 中含 Xposed 桥；`XposedBridge` 类可加载性。
- **可疑 so / 注入痕迹**：maps 中出现非应用自带、位于 `anon_inode` 或可执行匿名映射（动态注入的 so 常见特征）。

### L3 函数挂钩检测（Hooking）
- **Java 方法 hook**：反射读取关键方法 `ArtMethod` 的 `accessFlags` / 声明类，判断是否被替换为 native（Xposed 把 Java 方法改成 native 并改 entrypoint）；对比「预期修饰符」。
- **native inline hook**：读取目标函数（如 `open/openat/read/mmap/ptrace` 及 JNI 函数表项）前若干字节，匹配已知 trampoline 特征（ARM64 `LDR x16,#8; BR x16`、跳转桩、Frida Interceptor 的 `b`/`ldr` 桩），并检查是否落在非本模块内存页。
- **GOT/PLT hook**：校验 GOT 表项指向是否仍属于其定义所在的 ELF 模块。
- **调用栈完整性**：敏感操作执行时抓取调用栈，预期应来自本应用签名包内的类；出现 `frida`、`xposed`、未知 dex 即异常。
- **敏感转账函数专项**：`TransferService.commitTransfer()` 上叠加「入口校验 + 金额二次比对 + 栈校验」。

### L4 反篡改 / 自校验层（Anti-Tamper）
这是应对「检测函数被 hook 改返回值」的核心：
- **多通道交叉验证**：同一个事实用 ≥3 条独立路径采集（Java API / 读 proc 文件 / native raw syscall）。同一工件经两通道读取**内容真矛盾**时产出强信号 `CROSS_CHANNEL_MISMATCH`；某通道仅沉默时只产出弱线索 `CROSS_CHANNEL_GAP`（不单独阻断，避免误报）。攻击者要彻底骗过，必须同时 hook 全部通道。
- **native 函数指针 canary**：记录关键 native 探针在 ELF 内的预期地址范围，运行时比对函数指针是否被重定向到模块外。
- **检测函数自校验**：对 native 探针函数体做内存 CRC，与基线对比（基线在 so 加载后、可能被注入前尽早建立）。
- **重打包 / 签名校验**：比对运行时 APK 签名哈希与内置基线；重打包植入 hook 框架时签名必然变化。
- **Java 探针 canary 类**：一个声明了已知修饰符的「金丝雀」方法，定期检查其 ArtMethod 是否被改。

### L5 响应与远程证明层（Response & Attestation）
- **风险引擎**：聚合所有信号 → 加权、去重、按威胁族收敛 → 输出 `Verdict(NONE/LOW/MEDIUM/HIGH/BLOCK)` 与可解释理由。纯 Kotlin 实现，可在宿主机 JVM 单测。
- **本地 fail-closed**：达到 BLOCK 阈值时，敏感操作在**提交服务端之前**中止，并给出不暴露检测细节的中性错误（避免给攻击者反馈具体触发项）。
- **远程证明**：
  1. 服务端下发一次性 `nonce`（挑战）；
  2. 客户端把本次交易摘要 + 全量信号 + nonce 组装成 `AttestationPayload`，用设备私钥签名；
  3. 服务端验签、校验 nonce 未重放、独立复算风险、再决定放行。
  - 生产环境应使用 **Android Keystore 硬件支持密钥 + Key Attestation**（密钥不出 TEE/StrongBox，连 App 自己都拿不到私钥）。示例为可在无硬件环境演示，提供「软件签名（demo）」与「Keystore 硬件证明（生产路径）」两套实现，代码里明确标注差异。

---

## 3. 为什么攻击者难以伪造检测结论

| 攻击手法 | 本工程的对抗点 |
|---|---|
| Hook 单个检测 API 返回「干净」 | L4 多通道交叉验证：内容真矛盾给强信号 `CROSS_CHANNEL_MISMATCH`，沉默给弱线索 `CROSS_CHANNEL_GAP`；真实风险仍在其它独立通道高置信收敛 |
| Hook 全部 Java 检测 | 关键探针在 native，且用 raw syscall 绕过被 hook 的 libc |
| Hook native 探针 | L3 函数体/trampoline 检测 + L4 函数指针 canary + 内存 CRC 自校验 |
| 改 `/proc`、build 属性藏 Frida/模拟器 | 多数据源（硬件、传感器、maps、线程、端口）交叉，属性可改但难全改 |
| 重打包植入框架 | L4 APK 签名基线校验 |
| 直接伪造一个「健康」上报给服务端 | L5 设备私钥签名 + 服务端 nonce 防重放，无私钥签不出合法证明 |
| 重放旧的合法证明 | nonce 一次性，服务端拒绝重复 nonce |
| 篡改金额但不碰检测器 | 转账函数 L3 栈校验 + 金额在签名 payload 内，服务端比对金额 |

**没有银弹**：内核级 / 硬件级对手（定制内核、恶意 hypervisor、TEE 被攻破）超出用户态 RASP 能力边界，需结合 Play Integrity / 厂商 TEE 证明与服务端风控。

---

## 4. 误报治理（避免正常用户用不了）

1. **信号与判定分离**：探针只报事实+置信度，阻断阈值集中在风险引擎和服务端策略，可远程灰度调整，无需发版。
2. **多信号收敛才阻断**：单一弱信号（如某机型某个属性命中模拟器特征）最高只到 LOW，绝不 BLOCK。
3. **置信度 + 良性白名单**：已知厂商 ROM 的合法特征（部分国产 ROM 自带 root 管理、特定传感器缺失机型）进入 allowlist 降权。
4. **fail-closed 仅用于敏感操作**：检测到风险只冻结转账/改密，不影响查询等只读功能，降低误伤面。
5. **可解释证据留痕**：每个 verdict 带触发的 signal id 与证据，便于事后研判误报并调参。
6. **本地默认阈值保守**：真正高置信阻断（如 inline hook + 注入 so + 签名损坏同时命中）才本地硬阻断；灰度态把可疑但不确定的交给服务端决策。

---

## 5. 模块与目录

```
rasp-core/   纯 Kotlin（无 Android 依赖）：信号模型、风险引擎、策略、
             远程证明的载荷/签名/验签、白名单。可在宿主机 JVM 直接单测。
app/         Android 示例：环境/注入/hook/自校验探针（Java + JNI native），
             转账业务流程，攻击模拟入口，UI 展示检测结果。
  src/main/cpp/  native 探针：raw syscall、maps/线程扫描、inline/GOT hook 检测、
             函数体 CRC、ptrace 自检、JNI 函数表 canary。
mock-server/ Ktor 模拟银行后端：下发 nonce、验签、验重放、复算风险、裁决转账。
docs/        设计、威胁建模、攻击模拟手册、能力边界。
```

---

## 6. 模拟攻击与如何检验

见 `docs/ATTACK_SIMULATIONS.md`。提供 6 类可在示例里一键触发的模拟攻击，覆盖 L1–L5：
A1 Java 方法 hook（动态代理/字节码改写敏感函数）、A2 检测 API 欺骗（hook 检测器本身）、
A3 native inline hook（trampoline）、A4 Frida-like 痕迹注入（伪造 maps/线程/端口）、
A5 模拟器/root 伪装、A6 远程证明伪造（重放/篡改/无密钥签名）。每类都给出**预期被哪一层、哪个 signal 抓住**。

---

## 7. 能力边界（务必阅读）

- 这是**示例级**实现，侧重讲清分层与对抗思路；商业加固还需 obfuscator、控制流平坦化、字符串加密、反调试深挖、native 多态化等。
- 无法防御**内核态 rootkit、恶意 hypervisor、硬件/TEE 被攻陷**；这类对手应通过 Google Play Integrity API、厂商硬件证明和服务端行为风控覆盖。
- 示例的软件签名证明（demo signer）私钥在设备上，高手可提取；生产必须切到 Keystore 硬件密钥 + Key Attestation，代码已预留该路径。
- 检测与绕过是持续对抗，特征库（trampoline 签名、Frida 版本痕迹）会过时，需可远程更新策略。
- 本工程仅用于**授权的安全演练与防护研究**，攻击模拟代码只能作用于本示例 App 自身进程，不含攻击第三方应用的能力。
