#include "detectors.h"

#include <errno.h>
#include <sys/system_properties.h>

#include "obfuscate.h"
#include "proc.h"

namespace rootect {
namespace {

// Start of the fstype/source half of a mountinfo line. Everything before " - " is
// variable-length, so the separator is the only reliable anchor.
const char* after_separator(const char* line) {
    for (const char* p = line; *p; ++p) {
        if (p[0] == ' ' && p[1] == '-' && p[2] == ' ') return p + 3;
    }
    return nullptr;
}

// True for mount points on a partition that ships read-only.
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

// Flags root frameworks and remounted system partitions. Magisk's tmpfs mounts carry
// "magisk" as their mount source, which names it outright.
void scan_mounts(ScanOutcome& out) {
    auto path = ROOTECT_HIDE("/proc/self/mountinfo");
    auto magisk = ROOTECT_HIDE("magisk");
    auto apatch = ROOTECT_HIDE("apatch");
    auto ksu = ROOTECT_HIDE("KSU");
    auto modules = ROOTECT_HIDE("/adb/modules");

    auto res = for_each_line(path.c_str(), [&](const char* line, std::size_t) {
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

    if (!res.complete()) ++out.inconclusive;
}

// Probes one path, hiding the literal at its own call site. A plain table would sit in
// .rodata and hand over the whole list. -ENOENT is a real absence; anything else means we
// were not allowed to look.
#define ROOTECT_PROBE(out, lit, flag)                     \
    do {                                                  \
        auto _h = ROOTECT_HIDE(lit);                      \
        int _rc = path_probe(_h.c_str());                 \
        if (_rc == 0) (out).flags |= (flag);              \
        else if (_rc != -ENOENT) ++(out).inconclusive;    \
    } while (0)

// Flags root binaries left on disk. Excludes /data/adb: it is root-only, so an app gets
// EACCES there on a clean device too — no signal, just noise.
void scan_paths(ScanOutcome& out) {
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

// True when a property is set and equals `expected`.
bool prop_is(const char* key, const char* expected) {
    char value[PROP_VALUE_MAX] = {0};
    if (__system_property_get(key, value) <= 0) return false;
    return field_equals(value, expected) && value[0] != '\0';
}

// Flags an unlocked bootloader and test-keys builds. Verified Boot reports its state three
// ways; any one disagreeing with a locked device is enough. An unset property proves
// nothing either way.
void scan_properties(ScanOutcome& out) {
    auto vbs = ROOTECT_HIDE("ro.boot.verifiedbootstate");
    auto locked = ROOTECT_HIDE("ro.boot.flash.locked");
    auto vbmeta = ROOTECT_HIDE("ro.boot.vbmeta.device_state");
    auto tags = ROOTECT_HIDE("ro.build.tags");

    auto green = ROOTECT_HIDE("green");
    auto zero = ROOTECT_HIDE("0");
    auto unlocked = ROOTECT_HIDE("unlocked");
    auto testkeys = ROOTECT_HIDE("test-keys");

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

// Flags a kernel-side root framework. KernelSU and APatch hook prctl on a magic option and
// write their version back; a stock kernel fails with EINVAL without touching the buffer.
// The return value is ignored on purpose — the buffer being written at all is the finding.
void scan_kernel(ScanOutcome& out) {
    constexpr long kMagic = 0xDEADBEEF;
    constexpr long kCmdGetVersion = 2;

    int version = 0;
    rt_prctl(kMagic, kCmdGetVersion, reinterpret_cast<long>(&version), 0, 0);

    if (version > 0) out.flags |= NS_KERNEL_ROOT_SYSCALL;
}

} // namespace

// Runs every root check.
void scan_root(ScanOutcome& out) {
    scan_mounts(out);
    scan_paths(out);
    scan_properties(out);
    scan_kernel(out);
}

// Runs everything the native layer can detect.
ScanOutcome scan_all() {
    ScanOutcome out;
    scan_root(out);
    scan_hooks(out);
    return out;
}

} // namespace rootect
