#include <jni.h>

extern "C" JNIEXPORT jstring JNICALL
Java_io_github_rootect_Rootect_nativePing(JNIEnv *env, jobject /* thiz */) {
    return env->NewStringUTF("rootect-native-ok");
}
