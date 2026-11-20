#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <dirent.h>
#include <cstring>
#include <string>
#include <vector>

#include "rasp_core.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "rasp-native", __VA_ARGS__)

namespace {
using rasp::Finding;
using rasp::MapEntry;
using rasp::scan::parse_maps;
using rasp::scan::scan_maps_for_injection;
using rasp::scan::scan_thread_names;
using rasp::scan::scan_tcp_ports;
using rasp::scan::detect_inline_hook;
using rasp::scan::crc32;
using rasp::raw::read_file;

// 把 native Finding 转成 Kotlin 的 Finding 数据类（app 模块定义）。
jobject to_java(JNIEnv *env, const Finding &f) {
    jclass cls = env->FindClass("com/bank/rasp/demo/rasp/NativeFinding");
    if (!cls) return nullptr;
    jmethodID ctor = env->GetMethodID(
        cls, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;DLjava/lang/String;Ljava/lang/String;)V");
    jstring jid = env->NewStringUTF(f.id.c_str());
    jstring jfamily = env->NewStringUTF(f.family.c_str());
    jstring jsev = env->NewStringUTF(f.severity.c_str());
    jstring jev = env->NewStringUTF(f.evidence.c_str());
    jstring jch = env->NewStringUTF(f.channel.c_str());
    return env->NewObject(cls, ctor, jid, jfamily, jsev, f.confidence, jev, jch);
}

jobjectArray make_finding_array(JNIEnv *env, const std::vector<Finding> &findings) {
    jclass cls = env->FindClass("com/bank/rasp/demo/rasp/NativeFinding");
    jobjectArray arr = env->NewObjectArray(static_cast<jsize>(findings.size()), cls, nullptr);
    for (size_t i = 0; i < findings.size(); ++i) {
        jobject obj = to_java(env, findings[i]);
        if (obj) env->SetObjectArrayElement(arr, static_cast<jsize>(i), obj);
    }
    return arr;
}

// 通过 raw syscall 读取 /proc/self/maps
std::string read_maps() {
    std::string maps;
    read_file("/proc/self/maps", &maps);
    return maps;
}

// 列出所有线程名 /proc/self/task/*/comm（raw syscall 读文件）
std::vector<std::string> read_thread_names() {
    std::vector<std::string> names;
    DIR *dir = opendir("/proc/self/task");
    if (!dir) return names;
    struct dirent *de;
    while ((de = readdir(dir)) != nullptr) {
        if (de->d_name[0] == '.') continue;
        std::string comm_path = std::string("/proc/self/task/") + de->d_name + "/comm";
        std::string comm;
        if (read_file(comm_path.c_str(), &comm) && !comm.empty()) {
            names.push_back(comm);
        }
    }
    closedir(dir);
    return names;
}

// 解析本 so 在 maps 中的可执行段范围，用于函数指针合法性判断
bool find_module_range(const std::vector<MapEntry> &maps, const std::string &needle,
                       uintptr_t *start, uintptr_t *end) {
    uintptr_t lo = UINTPTR_MAX, hi = 0;
    bool found = false;
    for (const auto &m : maps) {
        if (m.path.find(needle) != std::string::npos) {
            found = true;
            lo = std::min(lo, m.start);
            hi = std::max(hi, m.end);
        }
    }
    if (found) { *start = lo; *end = hi; return true; }
    return false;
}

} // namespace

extern "C" {

// 综合 native 检测入口
JNIEXPORT jobjectArray JNICALL
Java_com_bank_rasp_demo_rasp_NativeBridge_nativeRunAll(JNIEnv *env, jclass) {
    std::vector<Finding> findings;

    // --- L2: maps 注入痕迹（raw syscall 读取，绕过被 hook 的 libc open/read） ---
    std::string maps_text = read_maps();
    auto maps = parse_maps(maps_text);
    auto map_findings = scan_maps_for_injection(maps);
    findings.insert(findings.end(), map_findings.begin(), map_findings.end());

    // --- L2: 线程名特征 ---
    auto names = read_thread_names();
    auto thread_findings = scan_thread_names(names);
    findings.insert(findings.end(), thread_findings.begin(), thread_findings.end());

    // --- L2: Frida 默认端口 ---
    std::string tcp;
    if (read_file("/proc/self/net/tcp", &tcp)) {
        auto port_findings = scan_tcp_ports(tcp);
        findings.insert(findings.end(), port_findings.begin(), port_findings.end());
    }

    // --- L3/L4: 对 libc 关键函数做 inline hook + 指针重定向检测 ---
    // 攻击者常 hook open/openat/read/ptrace/strcmp 等来隐藏痕迹或改流程。
    static const char *libc_targets[] = {
        "open", "openat", "read", "close", "ptrace", "strcmp", "strstr", "mmap"
    };
    uintptr_t libc_start = 0, libc_end = 0;
    if (find_module_range(maps, "libc.so", &libc_start, &libc_end)) {
        for (auto *name : libc_targets) {
            void *sym = dlsym(RTLD_DEFAULT, name);
            if (!sym) continue;
            uint8_t buf[32] = {0};
            // 直接读函数入口字节；正常情况下属于 libc 代码段且可读
            memcpy(buf, sym, sizeof(buf));
            auto hf = detect_inline_hook(name, sym, libc_start, libc_end, buf, sizeof(buf));
            findings.insert(findings.end(), hf.begin(), hf.end());
        }
    }

    // --- L4: 探针函数自校验（金丝雀）。对一个固定的 native 函数做 CRC，
    // 与 so 加载后尽早建立的基线比对（基线由 Kotlin 侧首次调用时缓存）。 ---
    // 此处仅返回当前 CRC，基线比对放在 Kotlin（NativeSelfCheck），避免把基线硬编码在 so 内被一并 patch。
    return make_finding_array(env, findings);
}

// 计算指定符号当前的函数体 CRC（用于 L4 自校验）
JNIEXPORT jint JNICALL
Java_com_bank_rasp_demo_rasp_NativeBridge_nativeCrcOfSymbol(JNIEnv *env, jclass, jstring jsym, jint len) {
    const char *sym = env->GetStringUTFChars(jsym, nullptr);
    void *addr = dlsym(RTLD_DEFAULT, sym);
    env->ReleaseStringUTFChars(jsym, sym);
    if (!addr || len <= 0) return -1;
    return static_cast<jint>(crc32(reinterpret_cast<const uint8_t *>(addr),
                                   static_cast<size_t>(len)));
}

// 用 raw syscall 读取任意 proc 文件（供 Kotlin 侧多通道交叉验证：与 Java File API 结果对比）
JNIEXPORT jstring JNICALL
Java_com_bank_rasp_demo_rasp_NativeBridge_nativeReadProc(JNIEnv *env, jclass, jstring jpath) {
    const char *path = env->GetStringUTFChars(jpath, nullptr);
    std::string content;
    bool ok = read_file(path, &content);
    env->ReleaseStringUTFChars(jpath, path);
    if (!ok) return nullptr;
    return env->NewStringUTF(content.c_str());
}

// 调试器/注入器跟踪检测：用 raw syscall 读 /proc/self/status 的 TracerPid。
// 相比一次性的 PTRACE_TRACEME（重复调用必失败、会持续误报），读 TracerPid 非破坏性、可重复，
// 且全程裸系统调用，绕过被 hook 的 libc fopen/read。
JNIEXPORT jboolean JNICALL
Java_com_bank_rasp_demo_rasp_NativeBridge_nativeIsTraced(JNIEnv *, jclass) {
    std::string status;
    if (!read_file("/proc/self/status", &status)) return JNI_FALSE;
    const std::string key = "TracerPid:";
    auto pos = status.find(key);
    if (pos == std::string::npos) return JNI_FALSE;
    int pid = 0;
    // 跳过 "TracerPid:" 与空白，解析数字；非 0 即存在 tracer（调试器/ptrace 注入）
    size_t i = pos + key.size();
    while (i < status.size() && (status[i] == ' ' || status[i] == '\t')) ++i;
    while (i < status.size() && status[i] >= '0' && status[i] <= '9') {
        pid = pid * 10 + (status[i] - '0');
        ++i;
    }
    return pid != 0 ? JNI_TRUE : JNI_FALSE;
}

} // extern "C"
