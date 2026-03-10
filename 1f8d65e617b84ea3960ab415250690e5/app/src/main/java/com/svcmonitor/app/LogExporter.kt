package com.svcmonitor.app

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object LogExporter {

    private fun timestamp(): String =
        SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())

    fun exportCsv(ctx: Context, events: List<SvcEvent>): File {
        val file = File(ctx.cacheDir, "svc_events_${timestamp()}.csv")
        file.bufferedWriter().use { w ->
            w.appendLine("seq,nr,name,pid,uid,comm,a0,a1,a2,a3,a4,a5,desc,caller,callerAddr,pc,fdPath,cloneFn")
            for (ev in events) {
                w.appendLine(listOf(
                    ev.seq, ev.nr, "\"${ev.name}\"", ev.pid, ev.uid,
                    "\"${ev.comm}\"",
                    ev.a0, ev.a1, ev.a2, ev.a3, ev.a4, ev.a5,
                    "\"${ev.desc.replace("\"", "'")}\"",
                    "\"${ev.caller}\"", "\"${ev.callerAddr}\"",
                    "\"${ev.pc}\"", "\"${ev.fdPath}\"", ev.cloneFn
                ).joinToString(","))
            }
        }
        return file
    }

    fun exportJson(ctx: Context, events: List<SvcEvent>): File {
        val file = File(ctx.cacheDir, "svc_events_${timestamp()}.json")
        val arr = JSONArray()
        for (ev in events) {
            val obj = JSONObject()
            obj.put("seq", ev.seq)
            obj.put("nr", ev.nr)
            obj.put("name", ev.name)
            obj.put("pid", ev.pid)
            obj.put("uid", ev.uid)
            obj.put("comm", ev.comm)
            obj.put("a0", ev.a0); obj.put("a1", ev.a1); obj.put("a2", ev.a2)
            obj.put("a3", ev.a3); obj.put("a4", ev.a4); obj.put("a5", ev.a5)
            obj.put("desc", ev.desc)
            obj.put("caller", ev.caller)
            obj.put("callerAddr", ev.callerAddr)
            obj.put("pc", ev.pc)
            obj.put("fdPath", ev.fdPath)
            obj.put("cloneFn", ev.cloneFn)
            arr.put(obj)
        }
        file.writeText(arr.toString(2))
        return file
    }

    fun createShareIntent(ctx: Context, file: File): Intent {
        val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.fileprovider", file)
        return Intent(Intent.ACTION_SEND).apply {
            type = if (file.name.endsWith(".csv")) "text/csv" else "application/json"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }
}
