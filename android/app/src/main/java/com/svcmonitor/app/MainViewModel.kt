package com.svcmonitor.app

import android.app.Application
import android.os.Handler
import android.os.Looper
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch

/**
 * MainViewModel -- state holder for SVCMonitor v8.3.
 * Uses viewModelScope + suspend KpmBridge calls.
 */
class MainViewModel(application: Application) : AndroidViewModel(application) {

    // ---- App selection ----
    private val _selectedApp = MutableLiveData<AppResolver.AppInfo?>()
    val selectedApp: LiveData<AppResolver.AppInfo?> = _selectedApp

    fun selectApp(app: AppResolver.AppInfo?) {
        _selectedApp.value = app
    }

    // ---- Preset selection ----
    private val _selectedPreset = MutableLiveData<Preset?>()
    val selectedPreset: LiveData<Preset?> = _selectedPreset

    fun selectPreset(preset: Preset?) {
        _selectedPreset.value = preset
    }

    // ---- Module status ----
    private val _status = MutableLiveData<ModuleStatus>()
    val status: LiveData<ModuleStatus> = _status

    // ---- Events ----
    private val _events = MutableLiveData<List<SvcEvent>>(emptyList())
    val events: LiveData<List<SvcEvent>> = _events

    private val _allCapturedEvents = mutableListOf<SvcEvent>()

    // ---- Log messages ----
    private val _log = MutableLiveData<String>("")
    val log: LiveData<String> = _log

    private val logBuffer = StringBuilder()

    private fun appendLog(msg: String) {
        logBuffer.append(msg).append('\n')
        if (logBuffer.length > 32000) {
            logBuffer.delete(0, logBuffer.length - 24000)
        }
        _log.postValue(logBuffer.toString())
    }

    fun uiLog(msg: String) {
        appendLog("[ui] $msg")
    }

    // ---- Polling ----
    private val handler = Handler(Looper.getMainLooper())
    private var polling = false
    private val pollRunnable = object : Runnable {
        override fun run() {
            if (polling) {
                pollOnce()
                handler.postDelayed(this, 2000)
            }
        }
    }

    // ---- Public actions ----

    fun refreshStatus() {
        viewModelScope.launch {
            try {
                val json = KpmBridge.status()
                val s = StatusParser.parseStatus(json)
                _status.postValue(s)
                appendLog("[status] enabled=${s.enabled} uid=${s.uid} tier2=${s.tier2} buffered=${s.eventsBuffered} total=${s.eventsTotal}")
            } catch (e: Exception) {
                appendLog("[error] status: ${e.message}")
            }
        }
    }

    fun startMonitoring() {
        viewModelScope.launch {
            try {
                // Set UID filter if an app is selected
                _selectedApp.value?.let { app ->
                    val uidResult = KpmBridge.setUid(app.uid)
                    appendLog("[uid] set to ${app.uid} (${app.label})")
                }

                // Apply preset if selected
                val preset = _selectedPreset.value ?: Preset.ALL_PRESETS.first()
                _selectedPreset.postValue(preset)
                KpmBridge.preset(preset.id)
                appendLog("[preset] applied: ${preset.name}")

                val result = KpmBridge.enable()
                val sr = StatusParser.parseSimple(result)
                appendLog("[enable] ${sr.msg.ifEmpty { sr.error.ifEmpty { "ok" } }}")
                refreshStatus()

                // Start polling
                polling = true
                handler.postDelayed(pollRunnable, 2000)
            } catch (e: Exception) {
                appendLog("[error] enable: ${e.message}")
            }
        }
    }

    fun stopMonitoring() {
        polling = false
        handler.removeCallbacks(pollRunnable)
        viewModelScope.launch {
            try {
                val result = KpmBridge.disable()
                val sr = StatusParser.parseSimple(result)
                appendLog("[disable] ${sr.msg.ifEmpty { sr.error.ifEmpty { "ok" } }}")
                refreshStatus()
            } catch (e: Exception) {
                appendLog("[error] disable: ${e.message}")
            }
        }
    }

    fun pollOnce() {
        viewModelScope.launch {
            try {
                val json = KpmBridge.drain()
                val dr = StatusParser.parseDrain(json)
                if (dr.events.isNotEmpty()) {
                    _allCapturedEvents.addAll(dr.events)
                    _events.postValue(_allCapturedEvents.toList())
                    appendLog("[drain] got ${dr.events.size} events (total captured: ${_allCapturedEvents.size})")
                }
            } catch (e: Exception) {
                appendLog("[error] drain: ${e.message}")
            }
        }
    }

    fun addNr(nr: Int) {
        viewModelScope.launch {
            KpmBridge.enableNr(nr)
            appendLog("[nr] enabled $nr (${StatusParser.nrToName(nr)})")
        }
    }

    fun removeNr(nr: Int) {
        viewModelScope.launch {
            KpmBridge.disableNr(nr)
            appendLog("[nr] disabled $nr (${StatusParser.nrToName(nr)})")
        }
    }

    fun setTier2(enabled: Boolean) {
        viewModelScope.launch {
            KpmBridge.tier2(enabled)
            appendLog("[tier2] ${if (enabled) "enabled" else "disabled"}")
            refreshStatus()
        }
    }

    fun clearEvents() {
        viewModelScope.launch {
            KpmBridge.clear()
            _allCapturedEvents.clear()
            _events.postValue(emptyList())
            appendLog("[clear] events cleared")
        }
    }

    fun exportCsv() {
        viewModelScope.launch {
            val ctx = getApplication<Application>()
            val evts = _allCapturedEvents.toList()
            if (evts.isEmpty()) {
                appendLog("[export] no events to export")
                return@launch
            }
            val file = LogExporter.exportCsv(ctx, evts)
            if (file != null) {
                appendLog("[export] CSV: ${file.absolutePath} (${evts.size} events)")
                val intent = LogExporter.createShareIntent(ctx, file, "text/csv")
                intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                ctx.startActivity(intent)
            } else {
                appendLog("[export] CSV export failed")
            }
        }
    }

    fun exportJson() {
        viewModelScope.launch {
            val ctx = getApplication<Application>()
            val evts = _allCapturedEvents.toList()
            if (evts.isEmpty()) {
                appendLog("[export] no events to export")
                return@launch
            }
            val file = LogExporter.exportJson(ctx, evts)
            if (file != null) {
                appendLog("[export] JSON: ${file.absolutePath} (${evts.size} events)")
                val intent = LogExporter.createShareIntent(ctx, file, "application/json")
                intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                ctx.startActivity(intent)
            } else {
                appendLog("[export] JSON export failed")
            }
        }
    }

    fun setSuperKey(key: String) {
        KpmBridge.setSuperKey(key)
        appendLog("[config] superkey updated")
    }

    override fun onCleared() {
        super.onCleared()
        polling = false
        handler.removeCallbacks(pollRunnable)
    }
}
