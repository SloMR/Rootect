#pragma once

// /proc readers built only on raw syscalls.
//
// On a rooted device /proc is attacker-influenced, so every line is treated as hostile:
// fixed buffers, bounds checks, over-long lines reported rather than silently dropped.
// Nothing here throws — a native fault would take down the host app.

#include <cstddef>
#include <fcntl.h>

#include "syscalls.h"

namespace rootect {

// Outcome of a line scan. A non-zero `truncated` means "could not check", never "nothing
// found": padding a line past the buffer is a way to hide it.
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
// look, which must not be reported as clean.
static inline int path_probe(const char* path) {
    return rt_faccessat(path, F_OK);
}

// Text helpers, hand-rolled so a hooked str* cannot skew a detector.

// True when `s` begins with `prefix`.
static inline bool starts_with(const char* s, const char* prefix) {
    while (*prefix) {
        if (*s++ != *prefix++) return false;
    }
    return true;
}

// True when `needle` appears anywhere in `haystack`.
static inline bool contains(const char* haystack, const char* needle) {
    for (const char* h = haystack; *h; ++h) {
        const char* a = h;
        const char* b = needle;
        while (*a && *b && *a == *b) { ++a; ++b; }
        if (*b == '\0') return true;
    }
    return false;
}

// True when `field` equals `value` up to the next space or end of line.
static inline bool field_equals(const char* field, const char* value) {
    while (*value) {
        if (*field != *value) return false;
        ++field;
        ++value;
    }
    return *field == ' ' || *field == '\0';
}

// Start of the nth space-separated field, or nullptr if the line is shorter.
static inline const char* nth_field(const char* line, int n) {
    const char* p = line;
    for (int i = 0; i < n; ++i) {
        while (*p && *p != ' ') ++p;
        while (*p == ' ') ++p;
        if (!*p) return nullptr;
    }
    return p;
}

// Value of a single hex digit, 0 for anything else.
static inline unsigned hex_val(char c) {
    if (c >= '0' && c <= '9') return unsigned(c - '0');
    if (c >= 'a' && c <= 'f') return unsigned(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return unsigned(c - 'A' + 10);
    return 0;
}

} // namespace rootect
