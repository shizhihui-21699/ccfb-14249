#include "rasp_core.h"

#include <cstring>
#include <cctype>
#include <cstdint>
#include <sstream>
#include <algorithm>

namespace rasp {
namespace scan {

// ---------------- maps 解析 ----------------

std::vector<MapEntry> parse_maps(const std::string &text) {
    std::vector<MapEntry> result;
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        // 形如:  70b1c00000-70b1c20000 r-xp 00000000 fd:00 1234  /path/lib.so
        MapEntry e;
        char perms[5] = {0};
        unsigned long start = 0, end = 0;
        // path 可选；先尝试带 path，再尝试无 path
        char path[512] = {0};
        int parsed = sscanf(line.c_str(), "%lx-%lx %4s %*x %*x:%*x %*lu %511[^\n]",
                            &start, &end, perms, path);
        if (parsed < 3) continue;
        e.start = start;
        e.end = end;
        e.readable = perms[0] == 'r';
        e.writable = perms[1] == 'w';
        e.executable = perms[2] == 'x';
        e.priv = perms[3] == 'p';
        if (parsed >= 4) {
            // 去掉前导空格
            char *p = path;
            while (*p == ' ') ++p;
            e.path = p;
        }
        result.push_back(e);
    }
    return result;
}

bool address_in_range(uintptr_t addr, uintptr_t start, uintptr_t end) {
    return addr >= start && addr < end;
}

// ---------------- 注入库特征 ----------------

static bool contains_ignore_case(const std::string &hay, const char *needle) {
    if (hay.empty()) return false;
    std::string h = hay;
    std::transform(h.begin(), h.end(), h.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    std::string n(needle);
    std::transform(n.begin(), n.end(), n.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return h.find(n) != std::string::npos;
}

bool looks_like_injection_lib(const std::string &path) {
    static const char *needles[] = {
        "frida-agent", "libfrida", "frida-gadget", "linjector",
        "libgadget", "xposed", "lsposed", "substrate", "libsubstrate",
        "edxposed", "riru", "zygisk", "shamiko", "magisk"
    };
    for (auto *n : needles) {
        if (contains_ignore_case(path, n)) return true;
    }
    return false;
}

std::vector<Finding> scan_maps_for_injection(const std::vector<MapEntry> &maps) {
    std::vector<Finding> out;
    bool found_frida = false;
    bool found_xposed = false;
    bool found_anon_exec = false;

    for (const auto &m : maps) {
        if (looks_like_injection_lib(m.path)) {
            if (contains_ignore_case(m.path, "frida") ||
                contains_ignore_case(m.path, "gadget")) {
                found_frida = true;
                out.push_back({"INJECTION_LIB::" + m.path, "INJECTION_FRAMEWORK",
                               "CRITICAL", 0.95,
                               "内存映射出现注入库: " + m.path, "PROC_FS"});
            } else {
                found_xposed = true;
                out.push_back({"INJECTION_LIB::" + m.path, "INJECTION_FRAMEWORK",
                               "STRONG", 0.85,
                               "内存映射出现 hook 框架库: " + m.path, "PROC_FS"});
            }
        }
        // 可执行且私有的匿名映射：动态注入的 shellcode / frida 代码段常见特征。
        // 这是启发式信号（JIT 也会产生），给中低置信度，交给风险引擎与其它信号收敛。
        if (m.executable && m.priv && m.path.empty()) {
            found_anon_exec = true;
        }
    }

    if (found_anon_exec && !found_frida) {
        out.push_back({"ANON_EXEC_MAPPING", "INJECTION_FRAMEWORK",
                       "WEAK", 0.45,
                       "存在可执行匿名私有映射，可能为动态注入 shellcode（也可能是 JIT）",
                       "PROC_FS"});
    }
    (void)found_xposed;
    return out;
}

// ---------------- 线程名扫描 ----------------

std::vector<Finding> scan_thread_names(const std::vector<std::string> &names) {
    std::vector<Finding> out;
    static const char *suspicious[] = {
        "gmain", "gum-js-loop", "gdbus", "pool-frida", "frida",
        "linjector", "pool-spawn"
    };
    for (const auto &name : names) {
        std::string trimmed = name;
        trimmed.erase(trimmed.find_last_not_of(" \t\r\n") + 1);
        for (auto *s : suspicious) {
            if (trimmed == s || contains_ignore_case(trimmed, s)) {
                out.push_back({"FRIDA_THREAD::" + trimmed, "INJECTION_FRAMEWORK",
                               "STRONG", 0.85,
                               "发现注入框架特征线程名: " + trimmed, "PROC_FS"});
                break;
            }
        }
    }
    return out;
}

// ---------------- 端口扫描 ----------------

std::vector<Finding> scan_tcp_ports(const std::string &tcp_text) {
    std::vector<Finding> out;
    // /proc/net/tcp 每行 local_address 形如 "0100007F:69A6"（十六进制端口）
    // frida 默认 27042=0x69A2, 27043=0x69A3
    static const char *frida_ports[] = {"69A2", "69A3"};
    std::istringstream ss(tcp_text);
    std::string line;
    bool first = true;
    while (std::getline(ss, line)) {
        if (first) { first = false; continue; } // 跳过表头
        // 行格式: "  sl  local_address rem_address ..."，local_address 是第 2 个字段，
        // 形如 0100007F:69A2。不能直接 find(':')，因为行首 slot 编号 "0:" 也带冒号。
        std::istringstream ls(line);
        std::string slot, addr;
        if (!(ls >> slot >> addr)) continue;
        auto colon = addr.find(':');
        if (colon == std::string::npos) continue;
        std::string port = addr.substr(colon + 1, 4);
        for (auto *p : frida_ports) {
            if (port == p) {
                out.push_back({"FRIDA_PORT::" + port, "INJECTION_FRAMEWORK",
                               "STRONG", 0.8,
                               "发现 Frida 默认 D-Bus 端口 0x" + port, "PROC_FS"});
            }
        }
    }
    return out;
}

// ---------------- inline hook 检测 ----------------

// 已知 trampoline 特征（按架构）。只保留高置信、低误报的「绝对跳转 gadget」，
// 刻意不把普通的相对跳转（arm64 裸 B、x86 裸 E9）单独当作 hook——
// bionic libc 里 open 等函数本身就可能以尾跳转（b openat）实现，宽松匹配会在干净机型误报。
// 对相对跳转的覆盖交给更可靠的「函数指针重定向」与「函数体 CRC 自校验」两条独立证据。
static bool __attribute__((unused))
matches_trampoline_arm64(const uint8_t *b, size_t n) {
    if (n < 16) return false;
    // Frida Interceptor 常见桩：LDR X16, #8 ; BR X16 ; <8 字节绝对地址>
    // 编码: 58000050  D61F0200
    return b[0] == 0x50 && b[1] == 0x00 && b[2] == 0x00 && b[3] == 0x58 &&
           b[4] == 0x00 && b[5] == 0x02 && b[6] == 0x1F && b[7] == 0xD6;
}

static bool __attribute__((unused))
matches_trampoline_x86_64(const uint8_t *b, size_t n) {
    if (n < 14) return false;
    // JMP [RIP+disp32]: FF 25 xx xx xx xx（绝对间接跳转 gadget）
    if (b[0] == 0xFF && b[1] == 0x25) return true;
    // PUSH/RET 式绝对跳转: 68 xx xx xx xx C3
    if (b[0] == 0x68 && b[5] == 0xC3) return true;
    // 注意：裸 E9（JMP rel32）不单独判 hook，理由同 arm64 裸 B，避免 libc 正常序言误报。
    return false;
}

std::vector<Finding> detect_inline_hook(const std::string &label,
                                        const void *target,
                                        uintptr_t module_start,
                                        uintptr_t module_end,
                                        const uint8_t *bytes,
                                        size_t n) {
    std::vector<Finding> out;
    const auto addr = reinterpret_cast<uintptr_t>(target);

    // 1) 函数指针是否已被重定向到其所属模块之外（GOT/PLT 或整体替换的强特征）
    if (!address_in_range(addr, module_start, module_end)) {
        out.push_back({"HOOK_PTR_REDIRECT::" + label, "NATIVE_HOOK",
                       "CRITICAL", 0.95,
                       "函数 " + label + " 指针 " + std::to_string(addr) +
                           " 落在所属模块范围 [" + std::to_string(module_start) +
                           "," + std::to_string(module_end) + ") 之外",
                       "NATIVE"});
        return out; // 已确认重定向，无需再看序言
    }

    // 2) 入口字节是否匹配已知 trampoline
    bool tramp = false;
#if defined(__aarch64__)
    tramp = matches_trampoline_arm64(bytes, n);
#elif defined(__x86_64__)
    tramp = matches_trampoline_x86_64(bytes, n);
#else
    // 主机测试：两套特征都尝试，便于用样例字节验证
    tramp = matches_trampoline_arm64(bytes, n) || matches_trampoline_x86_64(bytes, n);
#endif
    if (tramp) {
        std::string hex;
        char hbuf[4];
        for (size_t i = 0; i < n && i < 16; ++i) {
            snprintf(hbuf, sizeof(hbuf), "%02X ", bytes[i]);
            hex += hbuf;
        }
        out.push_back({"HOOK_NATIVE_INLINE::" + label, "NATIVE_HOOK",
                       "CRITICAL", 0.92,
                       "函数 " + label + " 入口匹配跳转桩特征，入口字节: " + hex,
                       "NATIVE"});
    }
    return out;
}

// ---------------- CRC32（函数体自校验） ----------------

uint32_t crc32(const uint8_t *data, size_t len) {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        init = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i)
        crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

} // namespace scan
} // namespace rasp
