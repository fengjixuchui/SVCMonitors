/* JNI bridge for KernelPatch supercall syscall */
#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define __NR_supercall 45

#define SUPERCALL_KPM_CONTROL     0x1022
#define SUPERCALL_KERNELPATCH_VER 0x1008

static long hash_key(const char *key) {
    long hash = 1000000007;
    for (int i = 0; key[i]; i++) hash = hash * 31 + key[i];
    return hash;
}

static long compact_cmd(const char *key, long cmd) {
    long ver_cmd = ((long)0x0a05 << 32) | (0x1158L << 16) | (cmd & 0xFFFF);
    long ver = syscall(__NR_supercall, key, ver_cmd);
    if (ver >= 0xa05) return ver_cmd;
    return (hash_key(key) & 0xFFFF0000) | cmd;
}

JNIEXPORT jstring JNICALL
Java_com_svcmonitor_app_jni_Supercall_nativeCtl0(JNIEnv *env, jclass clazz,
    jstring key, jstring name, jstring args)
{
    const char *k = (*env)->GetStringUTFChars(env, key, NULL);
    const char *n = (*env)->GetStringUTFChars(env, name, NULL);
    const char *a = (*env)->GetStringUTFChars(env, args, NULL);

    char out[65536];
    memset(out, 0, sizeof(out));

    long rc = syscall(__NR_supercall, k,
        compact_cmd(k, SUPERCALL_KPM_CONTROL),
        n, a, out, sizeof(out));

    (*env)->ReleaseStringUTFChars(env, key, k);
    (*env)->ReleaseStringUTFChars(env, name, n);
    (*env)->ReleaseStringUTFChars(env, args, a);

    if (rc < 0) {
        char err[256];
        snprintf(err, sizeof(err), "{\"ok\":false,\"error\":\"supercall failed rc=%ld\"}", rc);
        return (*env)->NewStringUTF(env, err);
    }
    return (*env)->NewStringUTF(env, out);
}
