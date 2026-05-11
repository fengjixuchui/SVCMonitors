package com.svcmonitor.app.jni

/**
 * JNI bridge to KernelPatch supercall syscall.
 * Calls syscall(45, ...) directly — no su needed.
 */
object Supercall {
    private var loaded = false

    fun ensureLoaded(): Boolean {
        if (loaded) return true
        return try {
            System.loadLibrary("supercall")
            loaded = true
            true
        } catch (e: UnsatisfiedLinkError) {
            false
        }
    }

    /**
     * Call KPM ctl0 native.
     * @param key SUPERKEY
     * @param name module name (e.g. "svc_monitor")
     * @param args ctl0 arguments (e.g. "status", "uid 12345", "preset re_basic")
     * @return JSON response string
     */
    @JvmStatic
    external fun nativeCtl0(key: String, name: String, args: String): String
}
