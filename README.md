# 手机银行运行时自我保护（RASP）示例工程

一套用 **Kotlin + JNI(C++) + Ktor** 实现的运行时应用自我保护示例：检测进程注入、函数挂钩、
模拟器/篡改系统，在确认被攻击时安全中止转账等敏感操作，并通过**设备私钥签名的远程证明**
让服务端可验证、攻击者无法伪造检测结论。

> 仅用于授权的安全演练与防护研究。攻击模拟只作用于本示例 App 自身进程，无攻击第三方能力。

## 它解决你提出的四个难点

| 难点 | 方案 |
|---|---|
| 注入工具会隐藏自己 | 多源**交叉验证**：Java API / `/proc` / native **裸系统调用**多通道独立采集，单源可藏、全源难藏 |
| 检测代码会被 hook 改返回值 | 关键探针下沉 native + raw syscall 绕过被 hook 的 libc；函数指针 canary + 函数体 CRC 自校验；检测「检测器口径矛盾」 |
| 厂商定制/老机型误报 | 信号与裁决分离、单弱信号永不阻断、多信号收敛才 BLOCK、白名单只降权不删除、阈值可服务端灰度 |
| 结论要让服务端知道且不被伪造 | nonce 挑战-应答 + 设备私钥签名（生产用 Keystore 硬件密钥）+ 防重放 + 计数器防回滚 + 服务端独立复算裁决 |

## 五层检测架构（详见 [docs/DESIGN.md](docs/DESIGN.md)）

```
L5 响应与远程证明   风险引擎裁决 / 本地 fail-closed / 签名 attestation / 服务端验签
L4 反篡改与自校验   多通道交叉验证、函数指针 canary、函数体 CRC、APK 签名基线
L3 函数挂钩检测     Java 调用栈完整性、native inline/GOT hook、trampoline 特征
L2 注入框架检测     Frida/Xposed/LSPosed 的 maps/线程名/端口/库特征
L1 环境层           模拟器、root/Magisk、调试器（多源交叉，弱信号）
```

## 模块

- `rasp-core/` —— 纯 Kotlin，无 Android 依赖：信号模型、风险引擎、白名单、远程证明签名/验签/nonce。**可在宿主机 JVM 单测**。
- `app/` —— Android 示例：各层探针（Kotlin + JNI）、转账业务、攻击模拟入口、演示 UI；`src/main/cpp` 为 raw syscall 与 native 扫描器。
- `mock-server/` —— Ktor 模拟银行后端：下发 nonce、验签、防重放、独立复算风险、裁决转账。
- `docs/` —— 设计与攻击模拟手册。

## 快速验证

```bash
# 1) 纯 JVM 测试（无需设备/Android SDK）
./gradlew :rasp-core:test :mock-server:test

# 2) native 扫描器主机自检
cd app/src/main/cpp
clang++ -std=c++17 host_test.cpp scanners.cpp raw_syscall.cpp -o /tmp/rasp_host_test && /tmp/rasp_host_test

# 3) 构建 Android App（需 Android SDK + NDK 26 + CMake，路径见 local.properties）
./gradlew :app:assembleDebug

# 4) 启动模拟服务端
./gradlew :mock-server:run
```

工具链可复现版本：JDK 17、Gradle 8.9（wrapper）、AGP 8.5.2、Kotlin 2.0.20、NDK 26.3、CMake 3.22.1。

## 能力边界

示例侧重讲清分层与对抗思路，**不能**防御内核级 rootkit、恶意 hypervisor、TEE 被攻陷；
软件签名（demo）私钥在设备上可被高手提取，生产必须切换 `KeystoreSigner`（硬件密钥，私钥不出 TEE/StrongBox）
并结合 Google Play Integrity 与服务端行为风控。详见 [docs/DESIGN.md](docs/DESIGN.md) 第 7 节。
