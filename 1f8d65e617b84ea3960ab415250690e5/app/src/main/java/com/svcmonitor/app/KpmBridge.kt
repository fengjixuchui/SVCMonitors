package com.svcmonitor.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * KpmBridge - CTL0 3-phase protocol for communicating with svc_monitor KPM module.
 *
 * Phase 1: rm output file
 * Phase 2: kpatch <superkey> kpm ctl0 svc_monitor '<command>'
 * Phase 3: cat output file -> JSON result
 */
object KpmBridge {

    private const val OUTPUT_PATH = "/data/local/tmp/svc_output.json"
    private var superKey = "testkey"

    fun setSuperKey(key: String) { superKey = key }
    fun getSuperKey(): String = superKey

    private suspend fun execRoot(cmd: String): String = withContext(Dispatchers.IO) {
        try {
            val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
            val reader = BufferedReader(InputStreamReader(proc.inputStream))
            val sb = StringBuilder()
            var line = reader.readLine()
            while (line != null) {
                sb.appendLine(line)
                line = reader.readLine()
            }
            proc.waitFor()
            sb.toString().trim()
        } catch (e: Exception) {
            ""
        }
    }

    private suspend fun ctl0(command: String): String {
        execRoot("rm -f $OUTPUT_PATH")
        execRoot("kpatch $superKey kpm ctl0 svc_monitor '$command'")
        delay(80)
        return execRoot("cat $OUTPUT_PATH")
    }

    suspend fun enable(): String = ctl0("enable")
    suspend fun disable(): String = ctl0("disable")
    suspend fun status(): String = ctl0("status")
    suspend fun drain(): String = ctl0("drain")
    suspend fun events(): String = ctl0("events")
    suspend fun clear(): String = ctl0("clear")
    suspend fun setUid(uid: Int): String = ctl0("uid $uid")
    suspend fun enableNr(nr: Int): String = ctl0("enable_nr $nr")
    suspend fun disableNr(nr: Int): String = ctl0("disable_nr $nr")
    suspend fun setNrs(nrs: String): String = ctl0("set_nrs $nrs")
    suspend fun enableAllNr(): String = ctl0("enable_all_nr")
    suspend fun disableAllNr(): String = ctl0("disable_all_nr")
    suspend fun preset(id: Int): String = ctl0("preset $id")
    suspend fun tier2(on: Boolean): String = ctl0("tier2 ${if (on) 1 else 0}")

    suspend fun isModuleLoaded(): Boolean {
        val out = execRoot("kpatch $superKey kpm list")
        return out.contains("svc_monitor")
    }

    /** One-click monitoring: enable + preset all + drain loop */
    suspend fun quickStart(uid: Int = 0): String {
        if (uid > 0) setUid(uid)
        ctl0("preset 9")
        return ctl0("enable")
    }
}
