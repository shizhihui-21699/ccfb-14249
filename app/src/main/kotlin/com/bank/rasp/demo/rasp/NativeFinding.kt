package com.bank.rasp.demo.rasp

/**
 * native 层（rasp_native.so）返回的原始发现。字段与 C++ 侧 rasp::Finding 一一对应，
 * 再由 [com.bank.rasp.demo.rasp.ProbeMapper] 转成 rasp-core 的跨平台 Signal。
 */
data class NativeFinding(
    val id: String,
    val family: String,
    val severity: String,
    val confidence: Double,
    val evidence: String,
    val channel: String
)
