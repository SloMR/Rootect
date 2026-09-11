#include "detect/detectors.h"

#include <errno.h>

#include "core/obfuscate.h"
#include "core/proc.h"

namespace rootect {
namespace {

// Backing file path of a maps line; defined below, declared here for scan_maps.
bool maps_path(const char* line, char* dst, std::size_t cap);

// Final path component of a slash-separated path.
const char* basename_of(const char* path) {
    const char* base = path;
    for (const char* p = path; *p; ++p) {
        if (*p == '/') base = p + 1;
    }
    return base;
}

// Case-insensitive match, rejected only when the match is followed by a lowercase letter, so
// "frida-agent-64.so" and "XposedBridge.jar" match but "com.example.friday" does not. The raw
// next char is tested, so an uppercase CamelCase boundary counts as a boundary, not continuation.
bool token_ci(const char* hay, const char* needle) {
    auto lower = [](char c) { return (c >= 'A' && c <= 'Z') ? char(c + 32) : c; };
    for (const char* h = hay; *h; ++h) {
        const char* a = h;
        const char* b = needle;
        while (*a && *b && lower(*a) == lower(*b)) { ++a; ++b; }
        if (*b == '\0' && (*a < 'a' || *a > 'z')) return true;
    }
    return false;
}

// Instrumentation flags for a mapped file's basename. Default names only; renamed artifacts slip.
unsigned instrumentation_flags(const char* base) {
    auto frida = ROOTECT_HIDE("frida");
    auto gum = ROOTECT_HIDE("gum-js");
    auto gadget = ROOTECT_HIDE("gadget");
    auto xposed = ROOTECT_HIDE("xposed");
    auto lspd = ROOTECT_HIDE("lspd");
    auto riru = ROOTECT_HIDE("riru");
    auto edxp = ROOTECT_HIDE("edxp");

    unsigned flags = 0;
    if (token_ci(base, frida.c_str()) || token_ci(base, gum.c_str()) ||
        token_ci(base, gadget.c_str())) {
        flags |= NS_FRIDA_LIBRARY;
    }
    if (token_ci(base, xposed.c_str()) || token_ci(base, lspd.c_str()) ||
        token_ci(base, riru.c_str()) || token_ci(base, edxp.c_str())) {
        flags |= NS_XPOSED_FRAMEWORK;
    }
    return flags;
}

// Flags instrumentation libraries mapped into this process, matched on the mapped file's
// basename so a package path like com.example.friday is not read as "frida".
void scan_maps(ScanOutcome& out) {
    auto maps = ROOTECT_HIDE("/proc/self/maps");

    auto res = for_each_line(maps.c_str(), [&](const char* line, std::size_t) {
        char path[256];
        if (!maps_path(line, path, sizeof(path))) return; // named file mappings only
        out.flags |= instrumentation_flags(basename_of(path));
    });

    if (!res.complete()) ++out.inconclusive;
}

// Flags Frida's own threads.
void scan_threads(ScanOutcome& out) {
    auto task_dir = ROOTECT_HIDE("/proc/self/task");
    auto gum_js = ROOTECT_HIDE("gum-js-loop");
    auto pool_frida = ROOTECT_HIDE("pool-frida");

    int dir = rt_openat(task_dir.c_str(), O_RDONLY | O_DIRECTORY);
    if (dir < 0) {
        ++out.inconclusive;
        return;
    }

    alignas(8) char buf[4096];
    for (;;) {
        long n = rt_getdents64(dir, buf, sizeof(buf));
        if (n == 0) break;                          // end of directory
        if (n < 0) { ++out.inconclusive; break; }   // could not enumerate — not "no threads"

        for (long off = 0; off + static_cast<long>(sizeof(rt_dirent64)) <= n;) {
            auto* e = reinterpret_cast<rt_dirent64*>(buf + off);
            unsigned short reclen = e->d_reclen;
            if (reclen < sizeof(rt_dirent64) || off + reclen > n) break; // malformed record
            const char* record_end = buf + off + reclen;
            off += reclen;

            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue; // skip . and ..

            // Build /proc/self/task/<tid>/comm
            char path[64];
            std::size_t p = 0;
            for (const char* s = task_dir.c_str(); *s && p < sizeof(path) - 1; ++s) path[p++] = *s;
            if (p < sizeof(path) - 1) path[p++] = '/';
            for (const char* s = e->d_name; *s && s < record_end && p < sizeof(path) - 1; ++s) {
                path[p++] = *s;
            }
            for (const char* s = "/comm"; *s && p < sizeof(path) - 1; ++s) path[p++] = *s;
            path[p] = '\0';

            int fd = rt_openat(path, O_RDONLY);
            if (fd < 0) {
                // -ENOENT means the thread exited mid-scan (benign); anything else is inconclusive.
                if (fd != -ENOENT) ++out.inconclusive;
                continue;
            }

            char name[64] = {0};
            long len = rt_read(fd, name, sizeof(name) - 1);
            rt_close(fd);
            if (len < 0) { ++out.inconclusive; continue; } // could not read this thread's name
            if (len == 0) continue;
            if (name[len - 1] == '\n') name[len - 1] = '\0';

            if (starts_with(name, gum_js.c_str()) || starts_with(name, pool_frida.c_str())) {
                out.flags |= NS_FRIDA_THREAD;
            }
        }
    }
    rt_close(dir);
}

// Flags a debugger or tracer holding us. Catches gdb and strace, not Frida — Frida detaches
// ptrace once injected, so TracerPid reads 0 under it.
void scan_tracer(ScanOutcome& out) {
    auto status = ROOTECT_HIDE("/proc/self/status");
    auto tracer = ROOTECT_HIDE("TracerPid:");

    auto res = for_each_line(status.c_str(), [&](const char* line, std::size_t) {
        if (!starts_with(line, tracer.c_str())) return;
        for (const char* p = line; *p; ++p) {
            if (*p >= '1' && *p <= '9') { // any non-zero pid
                out.flags |= NS_TRACER_ATTACHED;
                return;
            }
        }
    });

    if (!res.complete()) ++out.inconclusive;
}

// Its own address locates our executable segment. Needed because with
// extractNativeLibs=false the library is mapped out of base.apk and "librootect.so" never
// appears in /proc/self/maps.
__attribute__((noinline)) void* code_marker() {
    return reinterpret_cast<void*>(&code_marker);
}

// Backing file path of a maps line. False when the line has none.
bool maps_path(const char* line, char* dst, std::size_t cap) {
    const char* path = nth_field(line, 5);
    if (path == nullptr || *path != '/') return false;

    std::size_t n = 0;
    for (const char* q = path; *q && *q != ' ' && *q != '\n' && n < cap - 1; ++q) dst[n++] = *q;
    dst[n] = '\0';
    return n > 0;
}

// Address range of a maps line.
bool addr_range(const char* line, unsigned long& start, unsigned long& end) {
    start = 0;
    end = 0;
    const char* p = line;
    for (; *p && *p != '-'; ++p) start = start * 16 + hex_val(*p);
    if (*p != '-') return false;
    for (++p; *p && *p != ' '; ++p) end = end * 16 + hex_val(*p);
    return end > start;
}

// Flags an inline hook in our own code by diffing our executable pages against the file
// behind them. Catches the trampoline rather than the tool, so a renamed Frida still trips
// it. Executable pages only: PIC code is not relocated at load, so those bytes must still
// equal the file.
void scan_own_code(ScanOutcome& out) {
    auto maps = ROOTECT_HIDE("/proc/self/maps");
    const auto self_addr = reinterpret_cast<unsigned long>(code_marker());

    // Pass 1: which file backs our own code?
    char self_file[256] = {0};
    auto res1 = for_each_line(maps.c_str(), [&](const char* line, std::size_t) {
        if (self_file[0] != '\0') return;
        unsigned long start = 0, end = 0;
        if (!addr_range(line, start, end)) return;
        if (self_addr < start || self_addr >= end) return;
        maps_path(line, self_file, sizeof(self_file));
    });

    if (!res1.complete() || self_file[0] == '\0') {
        ++out.inconclusive;
        return;
    }

    // Read our own memory via /proc/self/mem: a raw pread returns -errno if a page was unmapped
    // or reprotected, where a direct read would fault. A failed read is unknown, never "clean".
    auto mem_path = ROOTECT_HIDE("/proc/self/mem");
    int fd_mem = rt_openat(mem_path.c_str(), O_RDONLY);
    if (fd_mem < 0) {
        ++out.inconclusive;
        return;
    }

    // Pass 2: check every executable segment of that file. The library maps as several
    // separate r-xp ranges and a hook only has to land in one of them.
    bool checked = false;
    bool mismatch = false;

    auto res2 = for_each_line(maps.c_str(), [&](const char* line, std::size_t) {
        if (mismatch) return;

        const char* perms = nth_field(line, 1);
        if (perms == nullptr || perms[2] != 'x') return;

        char file[256];
        if (!maps_path(line, file, sizeof(file))) return;
        if (!field_equals(file, self_file) || !field_equals(self_file, file)) return;

        unsigned long start = 0, end = 0, file_off = 0;
        if (!addr_range(line, start, end)) return;

        const char* off_field = nth_field(line, 2);
        if (off_field == nullptr) return;
        for (const char* q = off_field; *q && *q != ' '; ++q) file_off = file_off * 16 + hex_val(*q);

        int fd = rt_openat(file, O_RDONLY);
        if (fd < 0) {
            ++out.inconclusive;
            return;
        }

        char disk[1024];
        char live[1024];
        unsigned long size = end - start;
        for (unsigned long pos = 0; pos < size && !mismatch;) {
            unsigned long want = size - pos;
            if (want > sizeof(disk)) want = sizeof(disk);

            long dgot = rt_pread(fd, disk, want, static_cast<long long>(file_off + pos));
            if (dgot < 0) { ++out.inconclusive; break; } // could not read the file
            if (dgot == 0) break;                        // past end of file: zero-fill tail

            long lgot = rt_pread(fd_mem, live, static_cast<unsigned long>(dgot),
                                 static_cast<long long>(start + pos));
            if (lgot <= 0) { ++out.inconclusive; break; } // our page vanished or is unreadable

            long cmp = (lgot < dgot) ? lgot : dgot;
            for (long i = 0; i < cmp; ++i) {
                if (live[i] != disk[i]) { mismatch = true; break; }
            }
            checked = true;
            pos += static_cast<unsigned long>(cmp); // advance by bytes actually compared
        }
        rt_close(fd);
    });

    rt_close(fd_mem);

    if (!res2.complete()) ++out.inconclusive;
    if (mismatch) out.flags |= NS_CODE_MODIFIED;
    else if (!checked) ++out.inconclusive;
}

} // namespace

// Runs every instrumentation check.
void scan_hooks(ScanOutcome& out) {
    scan_maps(out);
    scan_threads(out);
    scan_tracer(out);
    scan_own_code(out);
}

} // namespace rootect
