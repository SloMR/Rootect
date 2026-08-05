#include "detectors.h"

#include <sys/system_properties.h>

#include "obfuscate.h"
#include "proc.h"

namespace rootect {
namespace {

// True when a property is set and contains `needle`.
bool prop_contains(const char* key, const char* needle) {
    char value[PROP_VALUE_MAX] = {0};
    if (__system_property_get(key, value) <= 0) return false;
    return contains(value, needle);
}

} // namespace

// Flags emulators and VMs. Matches the virtual hardware itself — QEMU device nodes and the
// hardware names of the Android emulator, Cuttlefish and VirtualBox images — rather than
// anything a build can simply rename.
void scan_emulator(ScanOutcome& out) {
    auto hardware = ROOTECT_HIDE("ro.hardware");
    auto model = ROOTECT_HIDE("ro.product.model");
    auto device = ROOTECT_HIDE("ro.product.device");
    auto qemu = ROOTECT_HIDE("ro.kernel.qemu");

    auto goldfish = ROOTECT_HIDE("goldfish");
    auto ranchu = ROOTECT_HIDE("ranchu");
    auto vbox = ROOTECT_HIDE("vbox");
    auto cutf = ROOTECT_HIDE("cutf");
    auto sdk_gphone = ROOTECT_HIDE("sdk_gphone");
    auto generic = ROOTECT_HIDE("generic");
    auto one = ROOTECT_HIDE("1");

    bool found =
        prop_contains(hardware.c_str(), goldfish.c_str()) ||
        prop_contains(hardware.c_str(), ranchu.c_str()) ||
        prop_contains(hardware.c_str(), vbox.c_str()) ||
        prop_contains(hardware.c_str(), cutf.c_str()) ||
        prop_contains(model.c_str(), sdk_gphone.c_str()) ||
        prop_contains(device.c_str(), generic.c_str()) ||
        prop_contains(qemu.c_str(), one.c_str());

    // QEMU exposes these device nodes to the guest; no physical handset has them.
    if (!found) {
        auto pipe = ROOTECT_HIDE("/dev/qemu_pipe");
        auto qemud = ROOTECT_HIDE("/dev/socket/qemud");
        auto gold_pipe = ROOTECT_HIDE("/dev/goldfish_pipe");

        found = path_probe(pipe.c_str()) == 0 || path_probe(qemud.c_str()) == 0 ||
                path_probe(gold_pipe.c_str()) == 0;
    }

    if (found) out.flags |= NS_EMULATOR;
}

} // namespace rootect
