#pragma once

// Safe /proc readers built only on raw syscalls.
//
// On a rooted device /proc is attacker-influenced, so every line is treated as hostile:
// fixed buffers, bounds checks, over-long lines reported rather than silently dropped.
// Never throws — a native fault here would take down the host app, which is worse than a
// missed detection.

#include <cstddef>
#include <fcntl.h>

#include "syscalls.h"

namespace rootect {

// Outcome of a line scan.
//
// `truncated` counts lines too long for the buffer. A detector must treat a non-zero count
// as "could not check", never as "nothing found": /proc content is attacker-influenced, so
// padding a line past the buffer is a way to hide it.
struct ScanResult {
    int error = 0;          // 0, or -errno from openat/read
    unsigned truncated = 0;

    bool complete() const { return error == 0 && truncated == 0; }
};

// Streams a file, calling fn(line, len) per NUL-terminated line.
template <typename Fn>
ScanResult for_each_line(const char* path, Fn&& fn) {
    ScanResult res;

    int fd = rt_openat(path, O_RDONLY);
    if (fd < 0) {
        res.error = fd;
        return res;
    }

    char chunk[512];
    char line[4096];
    std::size_t len = 0;
    bool dropping = false;

    for (;;) {
        long n = rt_read(fd, chunk, sizeof(chunk));
        if (n < 0) {
            res.error = static_cast<int>(n);
            break;
        }
        if (n == 0) break;

        for (long i = 0; i < n; ++i) {
            char c = chunk[i];
            if (c == '\n') {
                if (dropping) {
                    ++res.truncated;
                } else {
                    line[len] = '\0';
                    fn(line, len);
                }
                len = 0;
                dropping = false;
            } else if (len < sizeof(line) - 1) {
                line[len++] = c;
            } else {
                dropping = true;
            }
        }
    }

    if (res.error == 0) {
        if (dropping) {
            ++res.truncated;
        } else if (len > 0) {
            line[len] = '\0';
            fn(line, len); // trailing line with no newline
        }
    }

    rt_close(fd);
    return res;
}

// 0 if reachable, else -errno. -ENOENT means absent; -EACCES means we were not allowed to
// look, which is not the same answer and must not be reported as "clean".
static inline int path_probe(const char* path) {
    return rt_faccessat(path, F_OK);
}

// Prefix compare without libc, so a str* hook cannot skew a detector.
static inline bool starts_with(const char* s, const char* prefix) {
    while (*prefix) {
        if (*s++ != *prefix++) return false;
    }
    return true;
}

} // namespace rootect
