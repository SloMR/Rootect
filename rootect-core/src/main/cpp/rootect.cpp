#include <jni.h>

#include "obfuscate.h"
#include "proc.h"

// The single JNI entry point in release builds. Everything else stays hidden behind
// -fvisibility=hidden.
//
// Reads /proc/self/status through an obfuscated path and looks for a line the file always
// has. Finding it proves both halves at once: the raw syscalls work on this ABI, and the
// decrypted path was byte-exact — a wrong decode would open nothing.
extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_rootect_NativeBridge_selfTest(JNIEnv*, jobject) {
    auto path = ROOTECT_HIDE("/proc/self/status");
    auto marker = ROOTECT_HIDE("Name:");

    bool saw_marker = false;
    auto res = rootect::for_each_line(path.c_str(), [&](const char* line, std::size_t) {
        if (!saw_marker && rootect::starts_with(line, marker.c_str())) saw_marker = true;
    });

    return (res.complete() && saw_marker) ? JNI_TRUE : JNI_FALSE;
}

#ifndef NDEBUG
// Debug builds only — compiled out of release, so the shipped .so keeps exactly one
// exported symbol. Lets the instrumented tests drive for_each_line against fixture files,
// including the hostile cases that must not fault the host app.
//
// Returns {error, truncated, lines}.
extern "C" JNIEXPORT jintArray JNICALL
Java_io_github_rootect_NativeBridge_parserProbe(JNIEnv* env, jobject, jstring jpath) {
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

// Returns 0 if reachable, else -errno.
extern "C" JNIEXPORT jint JNICALL
Java_io_github_rootect_NativeBridge_pathProbe(JNIEnv* env, jobject, jstring jpath) {
    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (path == nullptr) return -1;

    int rc = rootect::path_probe(path);
    env->ReleaseStringUTFChars(jpath, path);
    return rc;
}
#endif
