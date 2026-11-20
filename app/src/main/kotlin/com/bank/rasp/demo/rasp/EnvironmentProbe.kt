package com.bank.rasp.demo.rasp

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Debug
import com.bank.rasp.core.model.Channel
import com.bank.rasp.core.model.Severity
import com.bank.rasp.core.model.Signal
import com.bank.rasp.core.model.ThreatFamily
import java.io.File

/**
 * L1 环境层探针：模拟器 / root / 调试器。
 *
 * 反误报要点：
 * - Build 属性极易被改且厂商 ROM 多样，单条命中只给 WEAK；
 * - 模拟器判定要求「Build 特征」与「硬件/驱动特征」两个以上独立来源同时命中才提高置信度；
 * - root 路径受 Magisk Hide 影响，只作弱信号，依赖 L2/L4 收敛。
 */
class EnvironmentProbe(private val appContext: Context) {

    private val nowMs get() = System.currentTimeMillis()

    fun run(): List<Signal> = buildList {
        addAll(emulatorSignals())
        addAll(rootSignals())
        addAll(debuggerSignals())
    }

    // ---------------- 模拟器 ----------------

    private fun emulatorSignals(): List<Signal> = buildList {
        // 来源 1：Build 属性（JAVA_API，易伪造，弱信号）
        val buildHits = EMU_BUILD_KEYWORDS.filter { kw ->
            listOf(DeviceInfo.hardware, DeviceInfo.product, DeviceInfo.board,
                DeviceInfo.model, DeviceInfo.fingerprint)
                .any { it.contains(kw, ignoreCase = true) }
        }
        if (buildHits.isNotEmpty()) {
            add(weak("EMULATOR::build", "Build 特征命中模拟器关键字: $buildHits", Channel.JAVA_API, 0.5))
        }

        // 来源 2：虚拟化驱动 / 设备节点（PROC_FS，比属性难伪造）
        val driverHits = EMU_DRIVER_PATHS.filter { File(it).exists() }
        if (driverHits.isNotEmpty()) {
            add(weak("EMULATOR::driver", "存在虚拟化驱动节点: $driverHits", Channel.PROC_FS, 0.7))
        }

        // 来源 3：硬件传感器（HARDWARE）。真机通常有加速度+陀螺+磁力，模拟器常缺失或为虚拟实现
        val sensorManager = appContext.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
        val hasAccel = sensorManager?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null
        val hasGyro = sensorManager?.getDefaultSensor(Sensor.TYPE_GYROSCOPE) != null
        if (!hasAccel && !hasGyro) {
            add(weak("EMU_SENSOR_MISSING", "加速度与陀螺仪均缺失，疑似虚拟设备", Channel.HARDWARE, 0.45))
        }

        // 来源 4：cpuinfo 中的虚拟化痕迹（PROC_FS）
        val cpuinfo = runCatching { File("/proc/cpuinfo").readText() }.getOrDefault("")
        if (cpuinfo.contains("goldfish", true) || cpuinfo.contains("ranchu", true)) {
            add(weak("EMULATOR::cpuinfo", "cpuinfo 含虚拟硬件代号", Channel.PROC_FS, 0.7))
        }
    }

    // ---------------- Root / Magisk ----------------

    private fun rootSignals(): List<Signal> = buildList {
        // su 二进制常见位置（Magisk Hide 可能隐藏，弱信号）
        val suHits = SU_PATHS.filter { File(it).exists() }
        if (suHits.isNotEmpty()) {
            add(weak("ROOT_SU::path", "发现 su 路径: $suHits", Channel.PROC_FS, 0.6))
        }
        // Magisk 挂载点与目录
        val magiskHits = MAGISK_PATHS.filter { File(it).exists() }
        if (magiskHits.isNotEmpty()) {
            add(weak("ROOT_SU::magisk", "发现 Magisk 痕迹: $magiskHits", Channel.PROC_FS, 0.6))
        }
        // root 管理类 App（包名查询，可能被隐藏）
        val pmHits = ROOT_PACKAGES.mapNotNull { pkg ->
            runCatching {
                appContext.packageManager.getPackageInfo(pkg, 0)
                pkg
            }.getOrNull()
        }
        if (pmHits.isNotEmpty()) {
            add(weak("ROOT_SU::packages", "发现 root 管理应用: $pmHits", Channel.JAVA_API, 0.55))
        }
        // 测试版/可调试系统属性
        if (android.os.Build.TAGS?.contains("test-keys", true) == true) {
            add(weak("ROOT_SU::testkeys", "系统镜像为 test-keys", Channel.JAVA_API, 0.4))
        }
    }

    // ---------------- 调试器（与 native TracerPid 交叉验证） ----------------

    private fun debuggerSignals(): List<Signal> = buildList {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            // 注意：这个 API 极易被 hook，单独不可信，作为交叉验证的一条腿
            add(weak("DEBUGGER::java", "Java 层报告调试器已连接", Channel.JAVA_API, 0.5))
        }
        if (NativeBridge.isAvailable && NativeBridge.nativeIsTraced()) {
            add(weak("DEBUGGER::tracerpid", "/proc/self/status 显示存在 TracerPid",
                Channel.RAW_SYSCALL, 0.8))
        }
    }

    private fun weak(id: String, evidence: String, channel: Channel, conf: Double) =
        Signal(id, familyOf(id), Severity.WEAK, conf, evidence, channel, nowMs)

    private fun familyOf(id: String): ThreatFamily = when {
        id.startsWith("EMULATOR") || id.startsWith("EMU_") -> ThreatFamily.EMULATOR
        id.startsWith("ROOT") -> ThreatFamily.ROOT
        id.startsWith("DEBUGGER") -> ThreatFamily.DEBUGGER
        else -> ThreatFamily.ROOT
    }

    companion object {
        val EMU_BUILD_KEYWORDS = listOf(
            "generic", "goldfish", "ranchu", "sdk_gphone", "vbox", "emulator", "sdk_google", "nox"
        )
        val EMU_DRIVER_PATHS = listOf(
            "/dev/qemu_pipe", "/dev/socket/qemud", "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace", "/dev/goldfish_pipe", "/system/bin/qemu-props",
            "/dev/vboxguest", "/dev/vboxuser"
        )
        val SU_PATHS = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/local/su",
            "/system/sd/xbin/su", "/su/bin/su", "/apex/com.android.runtime/bin/su"
        )
        val MAGISK_PATHS = listOf(
            "/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules",
            "/debug_ramdisk/.magisk", "/system/app/Magisk"
        )
        val ROOT_PACKAGES = listOf(
            "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser",
            "com.noshufou.android.su", "io.github.vvb2060.magisk"
        )
    }
}
