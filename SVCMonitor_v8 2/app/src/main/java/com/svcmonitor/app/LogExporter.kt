package com.svcmonitor.app

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * LogExporter -- exports captured SvcEvent lists to CSV and JSON files.
 * SVCMonitor v8.3
 */
object LogExporter {

    private fun timestamp(): String =
        SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())

    private fun csvQuote(s: String): String {
        val escaped = s.replace("\"", "\"\"")
        return "\"$escaped\""
    }

    /**
     * Export events to CSV file in app's cache directory.
     * Returns the File on success, or null on failure.
     */
    fun exportCsv(context: Context, events: List<SvcEvent>): File? {
        return try {
            val file = File(context.cacheDir, "svc_events_${timestamp()}.csv")
            file.bufferedWriter().use { w ->
                w.write("seq,nr,name,pid,uid,comm,a0,a1,a2,a3,a4,a5,desc,caller,pc,fdPath,cloneFn")
                w.newLine()
                for (ev in events) {
                    w.write(buildString {
                        append(ev.seq).append(',')
                        append(ev.nr).append(',')
                        append(csvQuote(ev.name)).append(',')
                        append(ev.pid).append(',')
                        append(ev.uid).append(',')
                        append(csvQuote(ev.comm)).append(',')
                        append(ev.a0).append(',')
                        append(ev.a1).append(',')
                        append(ev.a2).append(',')
                        append(ev.a3).append(',')
                        append(ev.a4).append(',')
                        append(ev.a5).append(',')
                        append(csvQuote(ev.desc)).append(',')
                        append(csvQuote(ev.caller)).append(',')
                        append(csvQuote(ev.pc)).append(',')
                        append(csvQuote(ev.fdPath)).append(',')
                        append(ev.cloneFn)
                    })
                    w.newLine()
                }
            }
            file
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Export events to JSON file in app's cache directory.
     * Returns the File on success, or null on failure.
     */
    fun exportJson(context: Context, events: List<SvcEvent>): File? {
        return try {
            val file = File(context.cacheDir, "svc_events_${timestamp()}.json")
            val arr = org.json.JSONArray()
            for (ev in events) {
                val obj = org.json.JSONObject()
                obj.put("seq", ev.seq)
                obj.put("nr", ev.nr)
                obj.put("name", ev.name)
                obj.put("pid", ev.pid)
                obj.put("uid", ev.uid)
                obj.put("comm", ev.comm)
                obj.put("a0", ev.a0)
                obj.put("a1", ev.a1)
                obj.put("a2", ev.a2)
                obj.put("a3", ev.a3)
                obj.put("a4", ev.a4)
                obj.put("a5", ev.a5)
                obj.put("desc", ev.desc)
                obj.put("caller", ev.caller)
                obj.put("pc", ev.pc)
                obj.put("fdPath", ev.fdPath)
                obj.put("cloneFn", ev.cloneFn)
                arr.put(obj)
            }
            val root = org.json.JSONObject()
            root.put("version", "8.3.0")
            root.put("exportTime", timestamp())
            root.put("count", events.size)
            root.put("events", arr)
            file.writeText(root.toString(2))
            file
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Create a share intent for the exported file via FileProvider.
     */
    fun createShareIntent(context: Context, file: File, mimeType: String): Intent {
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )
        return Intent(Intent.ACTION_SEND).apply {
            type = mimeType
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }
}
