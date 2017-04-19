#include <jni.h>
#include <string>

extern "C" {
JNIEXPORT jstring JNICALL
Java_com_sharker_ndkdemo_Hello_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from 1502B";
    return env->NewStringUTF(hello.c_str());
}

JNIEXPORT jstring JNICALL
Java_com_sharker_ndkdemo_Hello_stringFromJNIC(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from Hello World";
    return env->NewStringUTF(hello.c_str());
}
}