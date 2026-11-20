# 构建环境与排障

记录本示例在一台干净 macOS（Apple Silicon）上从零复现的步骤，以及实际踩到的坑。

## 版本基线
| 组件 | 版本 | 说明 |
|---|---|---|
| JDK | 17 (Temurin/OpenJDK) | AGP 8.5 要求 JDK 17；`export JAVA_HOME=/opt/homebrew/opt/openjdk@17` |
| Gradle | 8.9 | 用仓库自带 wrapper；系统若装的是 Gradle 9.x，**不能**直接用来构建 AGP 8.5 工程 |
| AGP | 8.5.2 | 见根 `build.gradle.kts` |
| Kotlin | 2.0.20 | |
| Android Platform | API 34 (compileSdk/targetSdk) | minSdk 26 |
| NDK | 26.3.11579264 (r26d) | 编 `rasp_native.so` |
| CMake | 3.22.1 | AGP 外部原生构建 |

## 从零搭建
```bash
# 1) JDK 17（macOS）
brew install openjdk@17
export JAVA_HOME=/opt/homebrew/opt/openjdk@17

# 2) Android cmdline-tools，再装平台/NDK/CMake
sdkmanager --sdk_root=$ANDROID_HOME \
  "platform-tools" "platforms;android-34" "ndk;26.3.11579264" "cmake;3.22.1"

# 3) 指向 SDK
echo "sdk.dir=$ANDROID_HOME" > local.properties   # 不入库

# 4) 构建/测试
./gradlew :rasp-core:test :mock-server:test      # 纯 JVM，最快
./gradlew :app:assembleDebug                      # 含 native 编译
```

## 实测踩坑与对策
1. **`gradle wrapper` 在 Gradle 9.x + 空目录报「does not contain a Gradle build」**
   9.x 的 wrapper 任务要求目录至少有 `settings.gradle(.kts)`。放一个最小 settings 再生成，或直接使用仓库内已提交的 wrapper。
2. **Kotlin DSL 注释是 `//` 不是 `#`**
   在 `.kts` 文件首行写 `# 注释` 会报 `Syntax error: Expecting an element`，且错误信息把中文切成奇怪片段。统一用 `//`。
3. **大文件下载易中断且续传会拼坏 zip**
   `curl -C -` 在 HTTP/2 流被重置后续传可能产生错位拼接，`unzip -t` 持续失败。
   对策：**不要续传，整包重下并用官方 SHA-256 校验**：
   ```bash
   curl --http1.1 -sS -L -o gradle.zip https://services.gradle.org/distributions/gradle-8.9-bin.zip
   shasum -a 256 gradle.zip   # 与官网 .sha256 比对
   ```
4. **`sdkmanager` 一次传多个包，后面的包可能静默不装**
   表现为任务退出码 0 但 `ndk/`、`platforms/` 目录为空。对策：**每个包单独安装并校验目录存在**，失败重试。
5. **`java.util.Base64` 需要 API 26**
   纯 Kotlin 模块里用了 JDK 的 `java.util.Base64`，Android 上 minSdk 必须 ≥26，否则老机型 `NoClassDefFoundError`。
6. **ptrace TRACEME 是一次性的**
   重复 `PTRACE_TRACEME` 第二次必失败，会持续误报「被调试」。改用读 `/proc/self/status` 的 `TracerPid`（非破坏性、可重复、可走 raw syscall）。
7. **inline hook 的宽松跳转特征会误报**
   bionic libc 的 `open` 可能本身就是 `b openat` 尾跳转；把「arm64 裸 B / x86 裸 E9」当 hook 会在干净机型误报。
   只保留绝对跳转 gadget（`LDR X16;BR X16`、`FF 25`、`push/ret`），相对跳转交给函数指针重定向 + CRC 自校验两条独立证据。
8. **`Method.getModifiers()` 反映声明期修饰符**
   多数 Java hook 框架改 ArtMethod entrypoint 而不改它，反射 `isNative` 会漏报。Java 层 hook 检测以**调用栈完整性**为主。
