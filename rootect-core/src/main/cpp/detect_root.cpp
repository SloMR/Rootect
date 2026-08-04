#include "detectors.h"

#include <errno.h>
#include <sys/system_properties.h>

#include "obfuscate.h"
#include "proc.h"

namespace rootect {
namespace {

bool contains(const char* haystack, const char* needle) {
    for (const char* h = haystack; *h; ++h) {
        const char* a = h;
        const char* b = needle;
        while (*a && *b && *a == *b) { ++a; ++b; }
        if (*b == '\0') return true;
    }
    return false;
}

// mountinfo: id parent maj:min root MOUNTPOINT options... - FSTYPE SOURCE superopts
// Everything before " - " is variable-length, so the separator is the only reliable anchor.
const char* after_separator(const char* line) {
    for (const char* p = line; *p; ++p) {
        if (p[0] == ' ' && p[1] == '-' && p[2] == ' ') return p + 3;
    }
    return nullptr;
}

const char* nth_field(const char* line, int n) {
    const char* p = line;
    for (int i = 0; i < n; ++i) {
        while (*p && *p != ' ') ++p;
        while (*p == ' ') ++p;
        if (!*p) return nullptr;
    }
    return p;
}

bool field_equals(const char* field, const char* value) {
    while (*value) {
        if (*field != *value) return false;
        ++field;
        ++value;
    }
    return *field == ' ' || *field == '\0';
}

// A mount point under one of the read-only system partitions being writable means the
// partition was remounted — classic system-modifying root.
bool is_system_partition(const char* mount_point) {
    static const char* const roots[] = {"/system", "/vendor", "/product", "/system_ext"};
    for (const char* r : roots) {
        const char* m = mount_point;
        const char* p = r;
        while (*p && *m == *p) { ++m; ++p; }
        if (*p == '\0' && (*m == ' ' || *m == '\0' || *m == '/')) return true;
    }
    return false;
}

void scan_mounts(ScanOutcome& out) {
    auto path = ROOTECT_HIDE("/proc/self/mountinfo");
    auto magisk = ROOTECT_HIDE("magisk");
    auto apatch = ROOTECT_HIDE("apatch");
    auto ksu = ROOTECT_HIDE("KSU");
    auto modules = ROOTECT_HIDE("/adb/modules");

    auto res = for_each_line(path.c_str(), [&](const char* line, std::size_t) {
        // The mount source names the framework outright: Magisk's tmpfs mounts carry
        // "magisk" as their source, and its files land under /debug_ramdisk/.magisk.
        if (contains(line, magisk.c_str()) || contains(line, apatch.c_str()) ||
            contains(line, modules.c_str())) {
            out.flags |= NS_MAGISK_ARTIFACT;
        }

        const char* tail = after_separator(line);
        if (tail != nullptr) {
            const char* source = nth_field(tail, 1);
            if (source != nullptr && field_equals(source, ksu.c_str())) {
                out.flags |= NS_MAGISK_ARTIFACT;
            }
        }

        const char* mount_point = nth_field(line, 4);
        const char* options = nth_field(line, 5);
        if (mount_point != nullptr && options != nullptr &&
            is_system_partition(mount_point) && options[0] == 'r' && options[1] == 'w') {
            out.flags |= NS_SYSTEM_WRITABLE;
        }
    });

    // A denied read or an over-long line means the answer is unknown, not clean.
    if (!res.complete()) ++out.inconclusive;
}

// A table of paths would sit in .rodata as plaintext, handing over the whole list. Each
// literal has to go through ROOTECT_HIDE at its own call site, which is what this macro
// forces. -ENOENT is a real "absent"; anything else means we were not allowed to look.
#define ROOTECT_PROBE(out, lit, flag)                     \
    do {                                                  \
        auto _h = ROOTECT_HIDE(lit);                      \
        int _rc = path_probe(_h.c_str());                 \
        if (_rc == 0) (out).flags |= (flag);              \
        else if (_rc != -ENOENT) ++(out).inconclusive;    \
    } while (0)

void scan_paths(ScanOutcome& out) {
    // Deliberately excludes anything under /data/adb: that directory is root-only, so an
    // app gets EACCES there on a clean device too. Probing it yields no signal and only
    // inflates the inconclusive count.
    ROOTECT_PROBE(out, "/system/bin/su", NS_SU_BINARY);
    ROOTECT_PROBE(out, "/system/xbin/su", NS_SU_BINARY);
    ROOTECT_PROBE(out, "/system/sbin/su", NS_SU_BINARY);
    ROOTECT_PROBE(out, "/vendor/bin/su", NS_SU_BINARY);
    ROOTECT_PROBE(out, "/sbin/su", NS_SU_BINARY);
    ROOTECT_PROBE(out, "/su/bin/su", NS_SU_BINARY);
    ROOTECT_PROBE(out, "/system/xbin/busybox", NS_SU_BINARY);
    ROOTECT_PROBE(out, "/system/bin/magisk", NS_MAGISK_ARTIFACT);
    ROOTECT_PROBE(out, "/system/bin/magiskpolicy", NS_MAGISK_ARTIFACT);
    ROOTECT_PROBE(out, "/sbin/.magisk", NS_MAGISK_ARTIFACT);
}

bool prop_is(const char* key, const char* expected) {
    char value[PROP_VALUE_MAX] = {0};
    if (__system_property_get(key, value) <= 0) return false;
    return field_equals(value, expected) && value[0] != '\0';
}

void scan_properties(ScanOutcome& out) {
    auto vbs = ROOTECT_HIDE("ro.boot.verifiedbootstate");
    auto locked = ROOTECT_HIDE("ro.boot.flash.locked");
    auto vbmeta = ROOTECT_HIDE("ro.boot.vbmeta.device_state");
    auto tags = ROOTECT_HIDE("ro.build.tags");

    auto green = ROOTECT_HIDE("green");
    auto zero = ROOTECT_HIDE("0");
    auto unlocked = ROOTECT_HIDE("unlocked");
    auto testkeys = ROOTECT_HIDE("test-keys");

    // Verified Boot reports its state three ways. Any one of them disagreeing with a
    // locked device is enough; an unset property is not evidence either way.
    char state[PROP_VALUE_MAX] = {0};
    if (__system_property_get(vbs.c_str(), state) > 0 && !field_equals(state, green.c_str())) {
        out.flags |= NS_BOOTLOADER_UNLOCKED;
    }
    if (prop_is(locked.c_str(), zero.c_str())) out.flags |= NS_BOOTLOADER_UNLOCKED;
    if (prop_is(vbmeta.c_str(), unlocked.c_str())) out.flags |= NS_BOOTLOADER_UNLOCKED;

    char build_tags[PROP_VALUE_MAX] = {0};
    if (__system_property_get(tags.c_str(), build_tags) > 0 &&
        contains(build_tags, testkeys.c_str())) {
        out.flags |= NS_TEST_KEYS_BUILD;
    }
}

void scan_kernel(ScanOutcome& out) {
    // KernelSU (and APatch's compatibility path) hook prctl on this magic option and
    // write their version back through the third argument. A stock kernel has no such
    // option and fails with EINVAL without touching the buffer.
    constexpr long kMagic = 0xDEADBEEF;
    constexpr long kCmdGetVersion = 2;

    int version = 0;
    rt_prctl(kMagic, kCmdGetVersion, reinterpret_cast<long>(&version), 0, 0);

    // The return value is deliberately ignored: some builds answer without a success
    // code. The buffer being written at all is what no stock kernel does.
    if (version > 0) out.flags |= NS_KERNEL_ROOT_SYSCALL;
}

} // namespace

ScanOutcome scan_root() {
    ScanOutcome out;
    scan_mounts(out);
    scan_paths(out);
    scan_properties(out);
    scan_kernel(out);
    return out;
}

} // namespace rootect
