package com.svcmonitor.app

import java.io.File

/**
 * KpmBridge -- communicates with the SVCMonitor kernel module via CTL0.
 *
 * 3-phase protocol:
 *   1. rm -f /data/local/tmp/svc_out.json
 *   2. kpatch <superkey> kpm ctl0 svc_monitor '<command>'
 *   3. cat /data/local/tmp/svc_out.json
 */
object KpmBridge {

    private const val KPATCH_PATH = "/data/adb/ap/bin/kpatch"
    private const val OUTPUT_PATH = "/data/local/tmp/svc_out.json"
    private const val MODULE_NAME = "svc_monitor"
    private const val DEFAULT_SUPER_KEY = "testkey"

    private var superKey: String = DEFAULT_SUPER_KEY

    fun setSuperKey(key: String) { superKey = key }
    fun getSuperKey(): String = superKey

    // ---- Low-level execution ----

    private suspend fun execRoot(vararg cmd: String): String {
        return kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            try {
                val proc = ProcessBuilder("su", "-c", cmd.joinToString(" "))
                    .redirectErrorStream(true)
                    .start()
                val output = proc.inputStream.bufferedReader().readText().trim()
                proc.waitFor()
                output
            } catch (e: Exception) {
                ""
            }
        }
    }

    private suspend fun ctl0(command: String): String {
        return kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            // Phase 1: remove old output
            execRoot("rm", "-f", OUTPUT_PATH)

            // Phase 2: execute kpatch ctl0 command
            execRoot(KPATCH_PATH, superKey, "kpm", "ctl0", MODULE_NAME, "'$command'")

            // Phase 3: read output file
            kotlinx.coroutines.delay(50) // brief delay for file write
            val result = execRoot("cat", OUTPUT_PATH)
            result
        }
    }

    // ---- Public API: Module control ----

    suspend fun enable(): String = ctl0("enable")

    suspend fun disable(): String = ctl0("disable")

    suspend fun status(): String = ctl0("status")

    suspend fun setUid(uid: Int): String = ctl0("uid $uid")

    suspend fun enableNr(nr: Int): String = ctl0("enable_nr $nr")

    suspend fun disableNr(nr: Int): String = ctl0("disable_nr $nr")

    suspend fun setNrs(nrs: List<Int>): String = ctl0("set_nrs ${nrs.joinToString(",")}")

    suspend fun enableAllNr(): String = ctl0("enable_all_nr")

    suspend fun disableAllNr(): String = ctl0("disable_all_nr")

    suspend fun preset(presetId: Int): String = ctl0("preset $presetId")

    suspend fun tier2(enabled: Boolean): String = ctl0("tier2 ${if (enabled) 1 else 0}")

    suspend fun drain(): String = ctl0("drain")

    suspend fun events(): String = ctl0("events")

    suspend fun clear(): String = ctl0("clear")

    // ---- Convenience ----

    suspend fun isModuleLoaded(): Boolean {
        val output = execRoot(KPATCH_PATH, superKey, "kpm", "list")
        return output.contains(MODULE_NAME)
    }
}
