package com.svcmonitor.app

import android.annotation.SuppressLint
import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.FileProvider
import androidx.lifecycle.ViewModelProvider
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.switchmaterial.SwitchMaterial
import java.io.File

class MainActivity : AppCompatActivity() {

    private lateinit var vm: SvcViewModel
    private lateinit var adapter: EventAdapter

    // views
    private lateinit var toolbar: Toolbar
    private lateinit var recyclerView: RecyclerView
    private lateinit var swipeRefresh: SwipeRefreshLayout
    private lateinit var fabAction: ExtendedFloatingActionButton
    private lateinit var tvStatusBar: TextView
    private lateinit var tvEmptyState: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var chipGroupFilter: ChipGroup

    // filter state
    private var filterCategory: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        vm = ViewModelProvider(this)[SvcViewModel::class.java]

        initViews()
        setupRecyclerView()
        setupToolbar()
        setupFab()
        setupSwipeRefresh()
        setupFilterChips()
        observeData()

        // initial status fetch
        vm.refreshStatus()
    }

    private fun initViews() {
        toolbar = findViewById(R.id.toolbar)
        recyclerView = findViewById(R.id.recyclerView)
        swipeRefresh = findViewById(R.id.swipeRefresh)
        fabAction = findViewById(R.id.fabAction)
        tvStatusBar = findViewById(R.id.tvStatusBar)
        tvEmptyState = findViewById(R.id.tvEmptyState)
        progressBar = findViewById(R.id.progressBar)
        chipGroupFilter = findViewById(R.id.chipGroupFilter)
    }

    private fun setupToolbar() {
        setSupportActionBar(toolbar)
        supportActionBar?.title = "SVC Monitor"
        supportActionBar?.subtitle = "v9.0 \u2022 ARM64 Syscall Tracer"
    }

    private fun setupRecyclerView() {
        adapter = EventAdapter { event -> showEventDetail(event) }
        recyclerView.layoutManager = LinearLayoutManager(this).apply {
            stackFromEnd = false
            reverseLayout = true  // newest on top
        }
        recyclerView.adapter = adapter
        recyclerView.itemAnimator = null  // disable animations for performance

        // auto-scroll FAB behavior
        recyclerView.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(rv: RecyclerView, dx: Int, dy: Int) {
                if (dy > 0) fabAction.shrink() else fabAction.extend()
            }
        })
    }

    private fun setupFab() {
        fabAction.setOnClickListener {
            if (vm.isMonitoring.value == true) {
                vm.stopMonitoring()
            } else {
                showQuickStartDialog()
            }
        }
    }

    private fun setupSwipeRefresh() {
        swipeRefresh.setColorSchemeResources(
            android.R.color.holo_blue_bright,
            android.R.color.holo_green_light,
            android.R.color.holo_orange_light,
            android.R.color.holo_red_light
        )
        swipeRefresh.setOnRefreshListener {
            vm.refreshStatus()
            swipeRefresh.isRefreshing = false
        }
    }

    private fun setupFilterChips() {
        // "All" chip
        val chipAll = Chip(this).apply {
            text = "All"
            isCheckable = true
            isChecked = true
            tag = null
        }
        chipGroupFilter.addView(chipAll)

        val categories = listOf("File I/O", "Filesystem", "Network", "Process", "Memory", "Security")
        for (cat in categories) {
            val chip = Chip(this).apply {
                text = cat
                isCheckable = true
                tag = cat
            }
            chipGroupFilter.addView(chip)
        }

        chipGroupFilter.setOnCheckedStateChangeListener { group, checkedIds ->
            if (checkedIds.isEmpty()) {
                filterCategory = null
                chipAll.isChecked = true
            } else {
                val chip = group.findViewById<Chip>(checkedIds.first())
                filterCategory = chip?.tag as? String
            }
            applyFilter()
        }
    }

    @SuppressLint("SetTextI18n")
    private fun observeData() {
        vm.events.observe(this) { events ->
            applyFilter()
            val isEmpty = events.isEmpty()
            tvEmptyState.visibility = if (isEmpty) View.VISIBLE else View.GONE
            recyclerView.visibility = if (isEmpty) View.GONE else View.VISIBLE
        }

        vm.status.observe(this) { st ->
            if (st != null) {
                val enabledStr = if (st.enabled) "ON" else "OFF"
                val tier2Str = if (st.tier2) "+T2" else ""
                tvStatusBar.text = "$enabledStr $tier2Str | UID:${st.uid} | " +
                    "Buf:${st.eventsBuffered} | Total:${st.eventsTotal} | ${st.version}"
                tvStatusBar.setBackgroundResource(
                    if (st.enabled) R.drawable.bg_status_on else R.drawable.bg_status_off
                )
            } else {
                tvStatusBar.text = "Module not responding"
                tvStatusBar.setBackgroundResource(R.drawable.bg_status_off)
            }
        }

        vm.toastMsg.observe(this) { msg ->
            if (msg.isNotEmpty()) {
                Snackbar.make(recyclerView, msg, Snackbar.LENGTH_SHORT).show()
            }
        }

        vm.isMonitoring.observe(this) { monitoring ->
            if (monitoring) {
                fabAction.text = "Stop"
                fabAction.setIconResource(android.R.drawable.ic_media_pause)
            } else {
                fabAction.text = "Monitor"
                fabAction.setIconResource(android.R.drawable.ic_media_play)
            }
        }

        vm.isBusy.observe(this) { busy ->
            progressBar.visibility = if (busy) View.VISIBLE else View.GONE
        }
    }

    private fun applyFilter() {
        val all = vm.events.value ?: emptyList()
        val filtered = if (filterCategory == null) all
        else {
            val nrs = SyscallInfo.CATEGORIES[filterCategory] ?: emptyList()
            all.filter { it.nr in nrs }
        }
        adapter.submitList(filtered) {
            if (filtered.isNotEmpty() && vm.isMonitoring.value == true) {
                recyclerView.scrollToPosition(0)
            }
        }
    }

    /* ====== Quick Start Dialog ====== */
    private fun showQuickStartDialog() {
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_quick_start, null)
        val etUid = view.findViewById<EditText>(R.id.etUid)
        val spinnerPreset = view.findViewById<Spinner>(R.id.spinnerPreset)
        val switchTier2 = view.findViewById<SwitchMaterial>(R.id.switchTier2)

        val presetNames = Preset.ALL_PRESETS.map { "${it.name} - ${it.description}" }
        spinnerPreset.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, presetNames)
        spinnerPreset.setSelection(8) // default: "all"

        // try resolve current foreground UID
        resolveTargetUid { uid -> etUid.setText(uid.toString()) }

        AlertDialog.Builder(this, com.google.android.material.R.style.ThemeOverlay_Material3_MaterialAlertDialog)
            .setTitle("Quick Start Monitoring")
            .setView(view)
            .setPositiveButton("Start") { _, _ ->
                val uid = etUid.text.toString().toIntOrNull() ?: 0
                val presetIdx = spinnerPreset.selectedItemPosition
                val presetName = Preset.ALL_PRESETS[presetIdx].name

                vm.quickStart(uid, presetName)

                if (switchTier2.isChecked) {
                    vm.enableTier2()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun resolveTargetUid(callback: (Int) -> Unit) {
        Thread {
            try {
                val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", "stat -c %u /proc/$(cat /proc/$(pidof com.android.shell)/status 2>/dev/null | grep PPid | awk '{print $2}') 2>/dev/null || echo 0"))
                val result = proc.inputStream.bufferedReader().readText().trim()
                val uid = result.toIntOrNull() ?: 0
                runOnUiThread { callback(uid) }
            } catch (e: Exception) {
                runOnUiThread { callback(0) }
            }
        }.start()
    }

    /* ====== Event Detail Dialog ====== */
    @SuppressLint("SetTextI18n")
    private fun showEventDetail(ev: SvcEvent) {
        val sheet = BottomSheetDialog(this, com.google.android.material.R.style.ThemeOverlay_Material3_BottomSheetDialog)
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_event_detail, null)

        view.findViewById<TextView>(R.id.tvDetailTitle).text = "#${ev.seq} ${ev.name} (NR:${ev.nr})"
        view.findViewById<TextView>(R.id.tvDetailProcess).text = "Process: ${ev.comm} (PID:${ev.pid}, UID:${ev.uid})"

        val sb = StringBuilder()
        sb.appendLine("Arguments:")
        sb.appendLine("  a0 = 0x${ev.a0.toString(16)}  (${ev.a0})")
        sb.appendLine("  a1 = 0x${ev.a1.toString(16)}  (${ev.a1})")
        sb.appendLine("  a2 = 0x${ev.a2.toString(16)}  (${ev.a2})")
        sb.appendLine("  a3 = 0x${ev.a3.toString(16)}  (${ev.a3})")
        sb.appendLine("  a4 = 0x${ev.a4.toString(16)}  (${ev.a4})")
        sb.appendLine("  a5 = 0x${ev.a5.toString(16)}  (${ev.a5})")

        if (ev.caller.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("Caller: ${ev.caller}")
            if (ev.callerAddr.isNotEmpty()) sb.appendLine("Caller Addr: 0x${ev.callerAddr}")
        }
        if (ev.pc.isNotEmpty()) sb.appendLine("PC: 0x${ev.pc}")
        if (ev.fdPath.isNotEmpty()) sb.appendLine("FD Path: ${ev.fdPath}")
        if (ev.cloneFn != 0L) sb.appendLine("Clone Fn: 0x${ev.cloneFn.toString(16)}")
        if (ev.desc.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("Parsed: ${ev.desc}")
        }

        view.findViewById<TextView>(R.id.tvDetailArgs).text = sb.toString()

        sheet.setContentView(view)
        sheet.show()
    }

    /* ====== Options Menu ====== */
    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.menu_settings -> { showSettingsDialog(); true }
            R.id.menu_preset -> { showPresetDialog(); true }
            R.id.menu_export -> { exportEvents(); true }
            R.id.menu_clear -> { vm.clearEvents(); true }
            R.id.menu_status -> { vm.refreshStatus(); true }
            else -> super.onOptionsItemSelected(item)
        }
    }

    /* ====== Settings Dialog ====== */
    private fun showSettingsDialog() {
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_settings, null)
        val etSuperKey = view.findViewById<EditText>(R.id.etSuperKey)
        val etSetUid = view.findViewById<EditText>(R.id.etSetUid)
        val switchTier2 = view.findViewById<SwitchMaterial>(R.id.switchSettingsTier2)

        etSuperKey.setText(KpmBridge.getSuperKey())
        vm.status.value?.let { st ->
            etSetUid.setText(st.uid.toString())
            switchTier2.isChecked = st.tier2
        }

        AlertDialog.Builder(this, com.google.android.material.R.style.ThemeOverlay_Material3_MaterialAlertDialog)
            .setTitle("Settings")
            .setView(view)
            .setPositiveButton("Apply") { _, _ ->
                val key = etSuperKey.text.toString()
                if (key.isNotEmpty()) KpmBridge.setSuperKey(key)

                val uid = etSetUid.text.toString().toIntOrNull()
                if (uid != null) vm.setUid(uid)

                if (switchTier2.isChecked) vm.enableTier2() else vm.disableTier2()
            }
            .setNegativeButton("Close", null)
            .show()
    }

    /* ====== Preset Dialog ====== */
    private fun showPresetDialog() {
        val names = Preset.ALL_PRESETS.map { "${it.name}: ${it.description}" }.toTypedArray()
        AlertDialog.Builder(this, com.google.android.material.R.style.ThemeOverlay_Material3_MaterialAlertDialog)
            .setTitle("Apply Preset")
            .setItems(names) { _, which ->
                vm.applyPreset(Preset.ALL_PRESETS[which].name)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /* ====== Export ====== */
    private fun exportEvents() {
        val events = vm.getEventsSnapshot()
        if (events.isEmpty()) {
            Snackbar.make(recyclerView, "No events to export", Snackbar.LENGTH_SHORT).show()
            return
        }
        Thread {
            try {
                val file = LogExporter.exportCsv(this, events)
                if (file != null) {
                    runOnUiThread { shareFile(file) }
                } else {
                    runOnUiThread {
                        Snackbar.make(recyclerView, "Export failed", Snackbar.LENGTH_SHORT).show()
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    Snackbar.make(recyclerView, "Export error: ${e.message}", Snackbar.LENGTH_SHORT).show()
                }
            }
        }.start()
    }

    private fun shareFile(file: File) {
        val uri = FileProvider.getUriForFile(this, "${packageName}.fileprovider", file)
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/csv"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(intent, "Share Events Log"))
    }
}
