#include "rasp_core.h"

#include <fcntl.h>
#include <unistd.h>

// 裸系统调用：直接 svc（arm64）/ syscall（x86_64）陷入内核，不经过 libc 导出符号。
// 这样即使攻击者 hook 了 libc.so 的 open/read/close，这里读到的仍是内核给出的真实数据。
namespace rasp {
namespace raw {

#if defined(__aarch64__)

// Linux arm64 syscall 号（见 asm-generic/unistd.h，架构通用号）
static constexpr long SYS_OPENAT_NR = 56;
static constexpr long SYS_READ_NR = 63;
static constexpr long SYS_CLOSE_NR = 57;
static constexpr long SYS_GETPID_NR = 172;
static constexpr long SYS_GETTID_NR = 178;

static long sc(long nr, long x0, long x1, long x2, long x3) {
    register long x8 __asm__("x8") = nr;
    register long r0 __asm__("x0") = x0;
    register long r1 __asm__("x1") = x1;
    register long r2 __asm__("x2") = x2;
    register long r3 __asm__("x3") = x3;
    __asm__ volatile("svc #0"
                     : "=r"(r0)
                     : "r"(x8), "r"(r0), "r"(r1), "r"(r2), "r"(r3)
                     : "memory", "cc");
    return r0;
}

int openat(const char *path, int flags) {
    // openat(dirfd=AT_FDCWD, path, flags, mode=0)
    return static_cast<int>(sc(SYS_OPENAT_NR, AT_FDCWD, reinterpret_cast<long>(path),
                               flags, 0));
}
long read(int fd, void *buf, size_t count) {
    return sc(SYS_READ_NR, fd, reinterpret_cast<long>(buf), static_cast<long>(count), 0);
}
int close(int fd) { return static_cast<int>(sc(SYS_CLOSE_NR, fd, 0, 0, 0)); }
int getpid() { return static_cast<int>(sc(SYS_GETPID_NR, 0, 0, 0, 0)); }
int gettid() { return static_cast<int>(sc(SYS_GETTID_NR, 0, 0, 0, 0)); }

#elif defined(__x86_64__)

static constexpr long SYS_READ_NR = 0;
static constexpr long SYS_OPEN_NR = 2;
static constexpr long SYS_CLOSE_NR = 3;
static constexpr long SYS_GETPID_NR = 39;
static constexpr long SYS_GETTID_NR = 186;
static constexpr long SYS_OPENAT_NR = 257;

static long sc(long nr, long a, long b, long c, long d, long e, long f) {
    long ret;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory", "cc");
    return ret;
}

int openat(const char *path, int flags) {
    return static_cast<int>(sc(SYS_OPENAT_NR, AT_FDCWD, reinterpret_cast<long>(path),
                               flags, 0, 0, 0));
}
long read(int fd, void *buf, size_t count) {
    return sc(SYS_READ_NR, fd, reinterpret_cast<long>(buf), static_cast<long>(count),
              0, 0, 0);
}
int close(int fd) { return static_cast<int>(sc(SYS_CLOSE_NR, fd, 0, 0, 0, 0, 0)); }
int getpid() { return static_cast<int>(sc(SYS_GETPID_NR, 0, 0, 0, 0, 0, 0)); }
int gettid() { return static_cast<int>(sc(SYS_GETTID_NR, 0, 0, 0, 0, 0, 0)); }

#else
// 其它架构（含主机编译）回退到 libc，仅用于主机逻辑单测；Android 产物只编 arm64/x86_64
int openat(const char *path, int flags) { return ::open(path, flags); }
long read(int fd, void *buf, size_t count) { return ::read(fd, buf, count); }
int close(int fd) { return ::close(fd); }
int getpid() { return ::getpid(); }
int gettid() { return (int)::gettid(); }
#endif

bool read_file(const char *path, std::string *out) {
    out->clear();
    int fd = openat(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[4096];
    while (true) {
        long n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            out->append(buf, static_cast<size_t>(n));
        } else if (n == 0) {
            break;
        } else {
            close(fd);
            return false;
        }
    }
    close(fd);
    return true;
}

} // namespace raw
} // namespace rasp
