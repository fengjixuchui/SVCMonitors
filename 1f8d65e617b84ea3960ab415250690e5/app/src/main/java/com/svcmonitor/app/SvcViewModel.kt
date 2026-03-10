package com.svcmonitor.app

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class SvcViewModel : ViewModel() {

    /* ---------- observable state ---------- */
    private val _status = MutableLiveData<ModuleStatus?>()
    val status: LiveData<ModuleStatus?> = _status

    private val _events = MutableLiveData<List<SvcEvent>>(emptyList())
    val events: LiveData<List<SvcEvent>> = _events

    private val _toastMsg = MutableLiveData<String>()
    val toastMsg: LiveData<String> = _toastMsg

    private val _isMonitoring = MutableLiveData(false)
    val isMonitoring: LiveData<Boolean> = _isMonitoring

    private val _isBusy = MutableLiveData(false)
    val isBusy: LiveData<Boolean> = _isBusy

    private var pollJob: Job? = null
    private var allEvents = mutableListOf<SvcEvent>()

    /* ---------- one-click monitoring ---------- */
    fun quickStart(uid: Int, preset: String) {
        viewModelScope.launch {
            _isBusy.value = true
            try {
                // 1. set UID
                val uidRes = KpmBridge.setUid(uid)
                val r1 = StatusParser.parseSimple(uidRes)
                if (!r1.ok) { _toastMsg.value = "Set UID failed: ${r1.msg}"; return@launch }

                // 2. apply preset
                val preRes = KpmBridge.preset(preset)
                val r2 = StatusParser.parseSimple(preRes)
                if (!r2.ok) { _toastMsg.value = "Preset failed: ${r2.msg}"; return@launch }

                // 3. enable
                val enRes = KpmBridge.enable()
                val r3 = StatusParser.parseSimple(enRes)
                if (!r3.ok) { _toastMsg.value = "Enable failed: ${r3.msg}"; return@launch }

                _toastMsg.value = "Monitoring started (UID=$uid, preset=$preset)"
                startPolling()
            } catch (e: Exception) {
                _toastMsg.value = "Error: ${e.message}"
            } finally {
                _isBusy.value = false
            }
        }
    }

    fun stopMonitoring() {
        viewModelScope.launch {
            _isBusy.value = true
            try {
                stopPolling()
                val res = KpmBridge.disable()
                val r = StatusParser.parseSimple(res)
                _toastMsg.value = if (r.ok) "Monitoring stopped" else "Disable failed: ${r.msg}"
            } catch (e: Exception) {
                _toastMsg.value = "Error: ${e.message}"
            } finally {
                _isBusy.value = false
            }
        }
    }

    /* ---------- polling ---------- */
    fun startPolling() {
        if (pollJob?.isActive == true) return
        _isMonitoring.value = true
        pollJob = viewModelScope.launch {
            while (isActive) {
                try {
                    val json = KpmBridge.drain()
                    val dr = StatusParser.parseDrain(json)
                    if (dr != null && dr.events.isNotEmpty()) {
                        allEvents.addAll(dr.events)
                        // keep last 2000 events max
                        if (allEvents.size > 2000) {
                            allEvents = allEvents.takeLast(2000).toMutableList()
                        }
                        _events.postValue(allEvents.toList())
                    }
                    // also refresh status
                    val sJson = KpmBridge.status()
                    _status.postValue(StatusParser.parseStatus(sJson))
                } catch (_: Exception) { }
                delay(500)
            }
        }
    }

    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
        _isMonitoring.value = false
    }

    /* ---------- status refresh ---------- */
    fun refreshStatus() {
        viewModelScope.launch {
            try {
                val json = KpmBridge.status()
                _status.value = StatusParser.parseStatus(json)
            } catch (e: Exception) {
                _toastMsg.value = "Status error: ${e.message}"
            }
        }
    }

    /* ---------- actions ---------- */
    fun enable() {
        viewModelScope.launch {
            _isBusy.value = true
            val res = KpmBridge.enable()
            val r = StatusParser.parseSimple(res)
            _toastMsg.value = if (r.ok) "Enabled" else "Enable failed: ${r.msg}"
            refreshStatus()
            _isBusy.value = false
        }
    }

    fun disable() {
        viewModelScope.launch {
            _isBusy.value = true
            val res = KpmBridge.disable()
            val r = StatusParser.parseSimple(res)
            _toastMsg.value = if (r.ok) "Disabled" else "Disable failed: ${r.msg}"
            refreshStatus()
            _isBusy.value = false
        }
    }

    fun setUid(uid: Int) {
        viewModelScope.launch {
            _isBusy.value = true
            val res = KpmBridge.setUid(uid)
            val r = StatusParser.parseSimple(res)
            _toastMsg.value = if (r.ok) "UID set to $uid" else "Set UID failed: ${r.msg}"
            refreshStatus()
            _isBusy.value = false
        }
    }

    fun applyPreset(name: String) {
        viewModelScope.launch {
            _isBusy.value = true
            val res = KpmBridge.preset(name)
            val r = StatusParser.parseSimple(res)
            _toastMsg.value = if (r.ok) "Preset $name applied" else "Preset failed: ${r.msg}"
            refreshStatus()
            _isBusy.value = false
        }
    }

    fun enableTier2() {
        viewModelScope.launch {
            _isBusy.value = true
            val res = KpmBridge.tier2Enable()
            val r = StatusParser.parseSimple(res)
            _toastMsg.value = if (r.ok) "Tier2 enabled" else "Tier2 failed: ${r.msg}"
            refreshStatus()
            _isBusy.value = false
        }
    }

    fun disableTier2() {
        viewModelScope.launch {
            _isBusy.value = true
            val res = KpmBridge.tier2Disable()
            val r = StatusParser.parseSimple(res)
            _toastMsg.value = if (r.ok) "Tier2 disabled" else "Tier2 failed: ${r.msg}"
            refreshStatus()
            _isBusy.value = false
        }
    }

    fun clearEvents() {
        allEvents.clear()
        _events.value = emptyList()
    }

    fun getEventsSnapshot(): List<SvcEvent> = allEvents.toList()

    override fun onCleared() {
        super.onCleared()
        pollJob?.cancel()
    }
}
