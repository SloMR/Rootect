#include <jni.h>
#include <sys/system_properties.h>

#include "detect/detectors.h"
#include "core/obfuscate.h"
#include "core/proc.h"

// Runs every native check. The tag catches malformed or naive replacements; it is not a MAC.
extern "C" JNIEXPORT jintArray JNICALL
Java_io_github_rootect_internal_jni_NativeBridge_scan(
        JNIEnv* env, jobject, jint nonce, jstring japk, jstring jexpected, jint sdk) {
    auto outcome = rootect::scan_all();
    if (jexpected != nullptr) {
        const char* apk = japk == nullptr ? nullptr : env->GetStringUTFChars(japk, nullptr);
        const char* expected = env->GetStringUTFChars(jexpected, nullptr);
        if (apk != nullptr && expected != nullptr) {
            int signing = rootect::signing_matches(apk, expected, sdk);
            if (signing == 0) outcome.facts |= rootect::NF_SIGNING_MATCH;
            if (signing == 1) outcome.facts |= rootect::NF_SIGNING_MISMATCH;
        }
        if (apk != nullptr) env->ReleaseStringUTFChars(japk, apk);
        if (expected != nullptr) env->ReleaseStringUTFChars(jexpected, expected);
    }
    jint out[4] = {
        static_cast<jint>(outcome.flags),
        static_cast<jint>(outcome.inconclusive),
        static_cast<jint>(outcome.facts),
        static_cast<jint>(rootect::result_tag(outcome.flags, outcome.inconclusive, outcome.facts,
                                              static_cast<unsigned>(nonce))),
    };
    jintArray arr = env->NewIntArray(4);
    if (arr != nullptr) env->SetIntArrayRegion(arr, 0, 4, out);
    return arr;
}

#ifndef NDEBUG
// Debug only. Proves both halves of the foundation at once: the raw syscalls work on this
// ABI, and the decrypted path was byte-exact — a wrong decode would open nothing.
extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_rootect_internal_jni_NativeProbes_selfTest(JNIEnv*, jobject) {
    auto path = ROOTECT_HIDE("/proc/self/status");
    auto marker = ROOTECT_HIDE("Name:");

    bool saw_marker = false;
    auto res = rootect::for_each_line(path.c_str(), [&](const char* line, std::size_t) {
        if (!saw_marker && rootect::starts_with(line, marker.c_str())) saw_marker = true;
    });

    return (res.complete() && saw_marker) ? JNI_TRUE : JNI_FALSE;
}

// Debug only. Drives for_each_line against fixture files, including the hostile cases.
// Returns {error, truncated, lines}.
extern "C" JNIEXPORT jintArray JNICALL
Java_io_github_rootect_internal_jni_NativeProbes_parserProbe(JNIEnv* env, jobject, jstring jpath) {
    jint out[3] = {0, 0, 0};

    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (path == nullptr) {
        out[0] = -1;
    } else {
        unsigned lines = 0;
        auto res = rootect::for_each_line(path, [&](const char*, std::size_t) { ++lines; });
        out[0] = res.error;
        out[1] = static_cast<jint>(res.truncated);
        out[2] = static_cast<jint>(lines);
        env->ReleaseStringUTFChars(jpath, path);
    }

    jintArray arr = env->NewIntArray(3);
    if (arr != nullptr) env->SetIntArrayRegion(arr, 0, 3, out);
    return arr;
}

// Debug only. Lets a test fail if the bit contract with NativeSignals.kt drifts.
extern "C" JNIEXPORT jint JNICALL
Java_io_github_rootect_internal_jni_NativeProbes_nativeSignalCount(JNIEnv*, jobject) {
    return static_cast<jint>(rootect::kNativeSignalCount);
}

// Debug only. Returns {found, serial, value_len} for a system property.
//
// Recon for property tampering: bionic bumps a property's serial on every write, and
// `ro.*` properties are written once at boot. Whether resetprop leaves that trace is
// the question this measures.
extern "C" JNIEXPORT jintArray JNICALL
Java_io_github_rootect_internal_jni_NativeProbes_propProbe(JNIEnv* env, jobject, jstring jname) {
    jint out[3] = {0, 0, 0};

    const char* name = env->GetStringUTFChars(jname, nullptr);
    if (name != nullptr) {
        const prop_info* pi = __system_property_find(name);
        if (pi != nullptr) {
            unsigned serial = __system_property_serial(pi);
            out[0] = 1;
            out[1] = static_cast<jint>(serial);
            out[2] = static_cast<jint>(serial >> 24);
        }
        env->ReleaseStringUTFChars(jname, name);
    }

    jintArray arr = env->NewIntArray(3);
    if (arr != nullptr) env->SetIntArrayRegion(arr, 0, 3, out);
    return arr;
}

// Debug only. Returns 0 if reachable, else -errno.
extern "C" JNIEXPORT jint JNICALL
Java_io_github_rootect_internal_jni_NativeProbes_pathProbe(JNIEnv* env, jobject, jstring jpath) {
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (path == nullptr) return -1;

    int rc = rootect::path_probe(path);
    env->ReleaseStringUTFChars(jpath, path);
    return rc;
}

// Debug only. Instrumentation flags scan_maps would set for a mapped file path.
extern "C" JNIEXPORT jint JNICALL
Java_io_github_rootect_internal_jni_NativeProbes_mapsProbe(JNIEnv* env, jobject, jstring jpath) {
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (path == nullptr) return 0;
    jint flags = static_cast<jint>(rootect::maps_probe(path));
    env->ReleaseStringUTFChars(jpath, path);
    return flags;
}
#endif
