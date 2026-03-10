package com.svcmonitor.app

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager

/**
 * AppResolver -- resolves installed applications for UID targeting.
 * SVCMonitor v8.3
 */
object AppResolver {

    data class AppInfo(
        val uid: Int,
        val packageName: String,
        val label: String
    ) {
        override fun toString(): String = "$label ($packageName) [uid=$uid]"
    }

    private var cachedApps: List<AppInfo>? = null

    fun getAllApps(context: Context): List<AppInfo> {
        cachedApps?.let { return it }

        val pm = context.packageManager
        val apps = pm.getInstalledApplications(PackageManager.MATCH_ALL)
            .map { ai ->
                AppInfo(
                    uid = ai.uid,
                    packageName = ai.packageName,
                    label = pm.getApplicationLabel(ai).toString()
                )
            }
            .distinctBy { it.uid }
            .sortedBy { it.label.lowercase() }

        cachedApps = apps
        return apps
    }

    fun searchApps(context: Context, query: String): List<AppInfo> {
        val q = query.lowercase().trim()
        if (q.isEmpty()) return getAllApps(context)
        return getAllApps(context).filter {
            it.label.lowercase().contains(q) ||
            it.packageName.lowercase().contains(q) ||
            it.uid.toString() == q
        }
    }

    fun invalidateCache() {
        cachedApps = null
    }
}
