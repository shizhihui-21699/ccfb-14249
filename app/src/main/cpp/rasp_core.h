#ifndef RASP_NATIVE_CORE_H
#define RASP_NATIVE_CORE_H

#include <cstdint>
#include <string>
#include <vector>

namespace rasp {

// ---------- 数据结构（与 Kotlin 侧探针结果对应） ----------

// 一条 native 检测发现。Kotlin 侧把它映射成 core 模块的 Signal。
struct Finding {
    std::string id;          // 信号 id，例如 HOOK_NATIVE_INLINE
    std::string family;      // ThreatFamily 名称
    std::string severity;    // Severity 名称
    double confidence;       // 0..1
    std::string evidence;    // 客观证据
    std::string channel;     // Channel 名称
};

// 内存映射条目（解析 /proc/self/maps 的一行）
struct MapEntry {
    uintptr_t start = 0;
    uintptr_t end = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool priv = false;
    std::string path;        // 可能为空（匿名映射）
};

// ---------- 裸系统调用（raw_syscall.cpp） ----------
// 关键：这些函数不经过 libc，因此即使 open/read 被 GOT/inline hook，
// 仍然能直接与内核通信，读取真实的 /proc 数据。
namespace raw {
// 以 raw syscall 打开文件，返回 fd（<0 表示失败）
int openat(const char *path, int flags);
// raw read
long read(int fd, void *buf, size_t count);
// raw close
int close(int fd);
// raw getpid
int getpid();
// raw gettid
int gettid();
// 读取整个文件（内部用 raw openat/read/close，完全绕开 libc）
bool read_file(const char *path, std::string *out);
}

// ---------- 扫描器（scanners.cpp，平台无关逻辑，可主机编译单测） ----------
namespace scan {

// 解析 maps 文本
std::vector<MapEntry> parse_maps(const std::string &maps_text);

// 在 maps 中查找注入/hook 框架痕迹（frida、xposed、gadget、可疑可执行匿名页等）
std::vector<Finding> scan_maps_for_injection(const std::vector<MapEntry> &maps);

// 扫描线程名（/proc/self/task/*/comm），调用方传入已读取的 comm 列表
std::vector<Finding> scan_thread_names(const std::vector<std::string> &names);

// 扫描 /proc/net/tcp 文本中的可疑端口（frida 默认 27042/27043）
std::vector<Finding> scan_tcp_ports(const std::string &tcp_text);

// 检测某函数入口是否被 inline hook。
// target: 函数地址；module_start/module_end: 该函数所属 ELF 的合法地址范围；
// bytes: 已读取到的入口字节（至少 16）。
std::vector<Finding> detect_inline_hook(const std::string &label,
                                        const void *target,
                                        uintptr_t module_start,
                                        uintptr_t module_end,
                                        const uint8_t *bytes,
                                        size_t n);

// 计算一段内存的 CRC32（用于检测函数体自校验）
uint32_t crc32(const uint8_t *data, size_t len);

// 判断地址是否落在某模块范围内
bool address_in_range(uintptr_t addr, uintptr_t start, uintptr_t end);

// 可疑 so 名称黑名单匹配（frida/xposed/substrate 等）
bool looks_like_injection_lib(const std::string &path);
}

} // namespace rasp
#endif
