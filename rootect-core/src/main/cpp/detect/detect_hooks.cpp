#include "detect/detectors.h"

#include <errno.h>

#include "core/obfuscate.h"
#include "core/proc.h"

namespace rootect {
namespace {

// Case-insensitive substring search, so a capitalised build name still matches.
bool contains_ci(const char* haystack, const char* needle) {
    auto lower = [](char c) { return (c >= 'A' && c <= 'Z') ? char(c + 32) : c; };
    for (const char* h = haystack; *h; ++h) {
        const char* a = h;
        const char* b = needle;
        while (*a && *b && lower(*a) == lower(*b)) { ++a; ++b; }
        if (*b == '\0') return true;
    }
    return false;
}

// Flags instrumentation libraries mapped into this process. Frida's agent arrives as a
// memfd named after itself.
void scan_maps(ScanOutcome& out) {
    auto maps = ROOTECT_HIDE("/proc/self/maps");

    auto frida = ROOTECT_HIDE("frida");
    auto gum = ROOTECT_HIDE("gum-js");
    auto gadget = ROOTECT_HIDE("gadget");

    auto xposed = ROOTECT_HIDE("xposed");
    auto lspd = ROOTECT_HIDE("lspd");
    auto riru = ROOTECT_HIDE("riru");
    auto edxp = ROOTECT_HIDE("edxp");

    auto res = for_each_line(maps.c_str(), [&](const char* line, std::size_t) {
        if (contains_ci(line, frida.c_str()) || contains_ci(line, gum.c_str()) ||
            contains_ci(line, gadget.c_str())) {
            out.flags |= NS_FRIDA_LIBRARY;
        }
        if (contains_ci(line, xposed.c_str()) || contains_ci(line, lspd.c_str()) ||
            contains_ci(line, riru.c_str()) || contains_ci(line, edxp.c_str())) {
            out.flags |= NS_XPOSED_FRAMEWORK;
        }
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
        if (n <= 0) break;

        for (long off = 0; off < n;) {
            auto* e = reinterpret_cast<rt_dirent64*>(buf + off);
            if (e->d_reclen == 0) break;
            off += e->d_reclen;

            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue; // skip . and ..

            // Build /proc/self/task/<tid>/comm
            char path[64];
            std::size_t p = 0;
            for (const char* s = task_dir.c_str(); *s && p < sizeof(path) - 1; ++s) path[p++] = *s;
            if (p < sizeof(path) - 1) path[p++] = '/';
            for (const char* s = e->d_name; *s && p < sizeof(path) - 1; ++s) path[p++] = *s;
            for (const char* s = "/comm"; *s && p < sizeof(path) - 1; ++s) path[p++] = *s;
            path[p] = '\0';

            int fd = rt_openat(path, O_RDONLY);
            if (fd < 0) continue;

            char name[64] = {0};
            long len = rt_read(fd, name, sizeof(name) - 1);
            rt_close(fd);
            if (len <= 0) continue;
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
        unsigned long size = end - start;
        for (unsigned long pos = 0; pos < size; pos += sizeof(disk)) {
            unsigned long want = size - pos;
            if (want > sizeof(disk)) want = sizeof(disk);

            long got = rt_pread(fd, disk, want, static_cast<long long>(file_off + pos));
            if (got <= 0) break; // past end of file: the tail is zero-fill, not a mismatch

            const char* mem = reinterpret_cast<const char*>(start + pos);
            for (long i = 0; i < got; ++i) {
                if (mem[i] != disk[i]) { mismatch = true; break; }
            }
            checked = true;
            if (mismatch) break;
        }
        rt_close(fd);
    });

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
