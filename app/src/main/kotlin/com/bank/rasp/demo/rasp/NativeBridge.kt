package com.bank.rasp.demo.rasp

/**
 * JNI 桥。所有方法对应 rasp_native.cpp 中的 extern "C" 函数。
 *
 * 关键设计：native 探针内部用裸系统调用读取 /proc，不经过可能已被 hook 的 libc，
 * 因此即便攻击者 hook 了 Java File API 或 libc open/read，这里拿到的仍是内核真实数据。
 */
object NativeBridge {
    private var loaded = false

    init {
        try {
            System.loadLibrary("rasp_native")
            loaded = true
        } catch (t: Throwable) {
            // 加载失败本身要被上层当作风险信号，而不是静默吞掉
            loaded = false
        }
    }

    val isAvailable: Boolean get() = loaded

    /** 运行全部 native 检测（maps/线程/端口/inline hook/指针重定向）。 */
    external fun nativeRunAll(): Array<NativeFinding>

    /** 计算指定符号当前函数体 CRC，用于 L4 自校验基线比对。 */
    external fun nativeCrcOfSymbol(symbol: String, length: Int): Int

    /** 用裸系统调用读取 proc 文件（多通道交叉验证用）。失败返回 null。 */
    external fun nativeReadProc(path: String): String?

    /** 通过 /proc/self/status 的 TracerPid 判断是否被 ptrace 跟踪。 */
    external fun nativeIsTraced(): Boolean
}
