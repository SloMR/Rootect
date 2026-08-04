#pragma once

// Raw syscalls via inline assembly, one backend per ABI.
//
// Every file/kernel probe goes through here rather than libc. `open`, `read`, `access`
// and friends are PLT entries an attacker hooks in one line; `svc #0` talks to the kernel
// directly, so a userspace hook on libc achieves nothing. This does NOT defend against a
// hostile kernel — KernelSU and APatch live below this line.

// Raw syscalls return -errno on failure, not -1 with errno set. Callers get the reason for
// free and must not collapse it: -ENOENT ("absent") and -EACCES ("not allowed to look") are
// different findings.

#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace rootect {

#if defined(__aarch64__)

static inline long rt_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory");
    return x0;
}

#elif defined(__arm__)

static inline long rt_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
    // Thumb reserves r7 as the frame pointer, so it can't be bound as a register variable.
    // Save it, load the syscall number, svc, then restore.
    register long r0 __asm__("r0") = a0;
    register long r1 __asm__("r1") = a1;
    register long r2 __asm__("r2") = a2;
    register long r3 __asm__("r3") = a3;
    register long r4 __asm__("r4") = a4;
    register long r5 __asm__("r5") = a5;
    __asm__ volatile("push {r7}\n\t"
                     "mov r7, %[nr]\n\t"
                     "svc #0\n\t"
                     "pop {r7}"
                     : "+r"(r0)
                     : [nr] "r"(n), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
                     : "memory");
    return r0;
}

#elif defined(__x86_64__)

static inline long rt_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
    long ret;
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}

#else
#error "rootect: no raw-syscall backend for this ABI"
#endif

// Thin wrappers. O_CLOEXEC so a probe never leaks a descriptor across exec.
static inline int rt_openat(const char* path, int flags) {
    return static_cast<int>(rt_syscall(__NR_openat, AT_FDCWD,
                                       reinterpret_cast<long>(path),
                                       flags | O_CLOEXEC, 0, 0, 0));
}

// Retries on EINTR: a signal arriving mid-read is not a failure, and reporting it as one
// would make a detector give up on a file it could have read.
static inline long rt_read(int fd, void* buf, unsigned long count) {
    for (;;) {
        long n = rt_syscall(__NR_read, fd, reinterpret_cast<long>(buf),
                            static_cast<long>(count), 0, 0, 0);
        if (n != -EINTR) return n;
    }
}

static inline int rt_close(int fd) {
    return static_cast<int>(rt_syscall(__NR_close, fd, 0, 0, 0, 0, 0));
}

// mode is F_OK / R_OK / X_OK. Returns 0 if the access is allowed.
static inline int rt_faccessat(const char* path, int mode) {
    return static_cast<int>(rt_syscall(__NR_faccessat, AT_FDCWD,
                                       reinterpret_cast<long>(path), mode, 0, 0, 0));
}

// Kernel-side root frameworks hook prctl and answer on a magic option number. A stock
// kernel has no such option and returns -EINVAL, so a non-error reply is the finding.
static inline long rt_prctl(long opt, long a1, long a2, long a3, long a4) {
    return rt_syscall(__NR_prctl, opt, a1, a2, a3, a4, 0);
}

} // namespace rootect
