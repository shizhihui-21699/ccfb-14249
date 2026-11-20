// 主机自检：仅编译平台无关的扫描器逻辑（scanners.cpp），用构造的样例数据验证。
// 在开发机上：clang++ -std=c++17 host_test.cpp scanners.cpp raw_syscall.cpp -o host_test && ./host_test
// 不链接 JNI / Android 库。
#include "rasp_core.h"
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

using namespace rasp;

static int g_pass = 0, g_fail = 0;
#define CHECK(cond)                                                            \
    do {                                                                       \
        if (cond) { ++g_pass; }                                                \
        else { ++g_fail; printf("FAIL: %s (line %d)\n", #cond, __LINE__); }   \
    } while (0)

static bool contains_id(const std::vector<Finding> &fs, const std::string &prefix) {
    for (const auto &f : fs) if (f.id.rfind(prefix, 0) == 0) return true;
    return false;
}

void test_parse_maps() {
    std::string text =
        "70b1c00000-70b1c20000 r-xp 00000000 fd:00 1234 /system/lib64/libc.so\n"
        "70b1c20000-70b1c21000 rw-p 00000000 00:00 0\n"
        "71a0000000-71a1000000 r-xp 00000000 fd:00 5678 /data/local/tmp/frida-agent.so\n";
    auto maps = scan::parse_maps(text);
    CHECK(maps.size() == 3);
    CHECK(maps[0].readable && maps[0].executable && maps[0].priv);
    CHECK(maps[0].path == "/system/lib64/libc.so");
    CHECK(maps[1].path.empty());
    CHECK(maps[2].path.find("frida-agent") != std::string::npos);
}

void test_frida_maps() {
    std::string text =
        "1000-2000 r-xp 00000000 00:00 0 /data/local/tmp/re.frida.server/frida-agent-64.so\n";
    auto maps = scan::parse_maps(text);
    auto f = scan::scan_maps_for_injection(maps);
    CHECK(contains_id(f, "INJECTION_LIB"));
    CHECK(f.front().family == "INJECTION_FRAMEWORK");
}

void test_anon_exec_is_weak_only() {
    // 单独的匿名可执行页只能是弱信号，不能直接当攻击
    std::string text = "3000-4000 rwxp 00000000 00:00 0\n";
    auto maps = scan::parse_maps(text);
    auto f = scan::scan_maps_for_injection(maps);
    CHECK(contains_id(f, "ANON_EXEC_MAPPING"));
    CHECK(f.front().severity == "WEAK");
    CHECK(f.front().confidence < 0.5);
}

void test_thread_names() {
    std::vector<std::string> names = {"main", "gum-js-loop", "gmain", "RenderThread"};
    auto f = scan::scan_thread_names(names);
    CHECK(f.size() == 2);
    CHECK(contains_id(f, "FRIDA_THREAD"));
}

void test_frida_ports() {
    // 27042 = 0x69A2
    std::string tcp =
        "  sl  local_address rem_address\n"
        "   0: 0100007F:69A2 00000000:0000 0A\n"
        "   1: 0100007F:1F90 00000000:0000 0A\n";
    auto f = scan::scan_tcp_ports(tcp);
    CHECK(f.size() == 1);
    CHECK(contains_id(f, "FRIDA_PORT"));
}

void test_inline_hook_arm64_trampoline() {
    // LDR X16,#8 ; BR X16 ; 地址占位
    uint8_t code[16] = {0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1F, 0xD6,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uintptr_t mod = 0x7000000000ULL;
    auto f = scan::detect_inline_hook("open", reinterpret_cast<void *>(mod + 0x100),
                                      mod, mod + 0x100000, code, sizeof(code));
    CHECK(contains_id(f, "HOOK_NATIVE_INLINE"));
}

void test_pointer_redirect() {
    // 函数指针落在模块外 → 直接判重定向，最高优先
    uint8_t code[16] = {0};
    uintptr_t mod = 0x7000000000ULL;
    uintptr_t outside = 0x7100000000ULL;
    auto f = scan::detect_inline_hook("read", reinterpret_cast<void *>(outside),
                                      mod, mod + 0x100000, code, sizeof(code));
    CHECK(contains_id(f, "HOOK_PTR_REDIRECT"));
    CHECK(f.front().severity == "CRITICAL");
}

void test_clean_function_no_hook() {
    // 正常 aarch64 序言：STP X29, X30, [SP,#-...]!  (0xA9...)，非跳转桩
    uint8_t code[16] = {0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uintptr_t mod = 0x7000000000ULL;
    auto f = scan::detect_inline_hook("open", reinterpret_cast<void *>(mod + 0x200),
                                      mod, mod + 0x100000, code, sizeof(code));
    CHECK(f.empty());
}

void test_legitimate_tail_call_is_not_flagged() {
    // 回归：bionic libc 的 open 可能实现为 "b openat"（裸 B imm，编码 0x14 开头）。
    // 函数指针仍在 libc 模块内时，这是合法尾跳转，绝不能判成 inline hook（反误报）。
    uint8_t code[16] = {0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uintptr_t mod = 0x7000000000ULL;
    auto f = scan::detect_inline_hook("open", reinterpret_cast<void *>(mod + 0x300),
                                      mod, mod + 0x100000, code, sizeof(code));
    CHECK(f.empty());
}

void test_crc_stable_and_sensitive() {
    uint8_t a[32] = {0};
    uint8_t b[32] = {0};
    b[0] = 0x01;
    uint32_t c1 = scan::crc32(a, sizeof(a));
    uint32_t c2 = scan::crc32(a, sizeof(a));
    uint32_t c3 = scan::crc32(b, sizeof(b));
    CHECK(c1 == c2);       // 同样输入 CRC 稳定（自校验基线可靠）
    CHECK(c1 != c3);       // 改一个字节 CRC 即变（能发现函数体被 patch）
}

void test_injection_lib_matcher() {
    CHECK(scan::looks_like_injection_lib("/data/tmp/frida-agent-64.so"));
    CHECK(scan::looks_like_injection_lib("/x/LSPosed/core.so"));
    CHECK(!scan::looks_like_injection_lib("/system/lib64/libc.so"));
}

int main() {
    test_parse_maps();
    test_frida_maps();
    test_anon_exec_is_weak_only();
    test_thread_names();
    test_frida_ports();
    test_inline_hook_arm64_trampoline();
    test_pointer_redirect();
    test_clean_function_no_hook();
    test_legitimate_tail_call_is_not_flagged();
    test_crc_stable_and_sensitive();
    test_injection_lib_matcher();
    printf("\nnative host tests: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
