package com.svcmonitor.app

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager

data class AppInfo(val packageName: String, val label: String, val uid: Int)

object AppResolver {
    private var cache: List<AppInfo>? = null

    fun getAllApps(ctx: Context): List<AppInfo> {
        cache?.let { return it }
        val pm = ctx.packageManager
        val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            .map { ai ->
                AppInfo(
                    packageName = ai.packageName,
                    label = pm.getApplicationLabel(ai).toString(),
                    uid = ai.uid
                )
            }
            .sortedBy { it.label.lowercase() }
        cache = apps
        return apps
    }

    fun searchApps(ctx: Context, query: String): List<AppInfo> {
        val q = query.lowercase()
        return getAllApps(ctx).filter {
            it.label.lowercase().contains(q) || it.packageName.lowercase().contains(q)
        }
    }

    fun invalidateCache() { cache = null }
}
