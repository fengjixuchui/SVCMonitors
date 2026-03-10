package com.svcmonitor.app

import android.app.AlertDialog
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.TextUtils
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider

/**
 * MainActivity -- 4-tab programmatic UI for SVCMonitor v8.3.
 * Tabs: Control | Events | Filter | Settings
 * No XML layouts -- all views created in code.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var vm: MainViewModel
    private lateinit var tabHost: LinearLayout
    private lateinit var contentFrame: FrameLayout

    // Tab views
    private lateinit var controlView: View
    private lateinit var eventsView: View
    private lateinit var filterView: View
    private lateinit var settingsView: View

    // Control tab widgets
    private lateinit var statusText: TextView
    private lateinit var logText: TextView

    // Events tab widgets
    private lateinit var eventsListLayout: LinearLayout
    private lateinit var eventsCountText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        vm = ViewModelProvider(this)[MainViewModel::class.java]

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        // Header
        root.addView(createHeader())

        // Tab bar
        tabHost = createTabBar()
        root.addView(tabHost)

        // Content frame
        contentFrame = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f
            )
        }
        root.addView(contentFrame)

        // Create all tab content views
        controlView = createControlTab()
        eventsView = createEventsTab()
        filterView = createFilterTab()
        settingsView = createSettingsTab()

        // Show control tab by default
        switchTab(0)

        setContentView(root)

        // Observe data
        observeViewModel()

        // Initial status refresh
        vm.refreshStatus()
    }

    // ---- Header ----

    private fun createHeader(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(8))
            setBackgroundColor(Color.parseColor("#1a237e"))

            addView(TextView(this@MainActivity).apply {
                text = "SVCMonitor v8.3"
                setTextColor(Color.WHITE)
                textSize = 20f
                typeface = Typeface.DEFAULT_BOLD
            })
            addView(TextView(this@MainActivity).apply {
                text = "ARM64 SVC Syscall Monitor -- Pixel 6 / Android 12"
                setTextColor(Color.parseColor("#b0bec5"))
                textSize = 12f
            })
        }
    }

    // ---- Tab Bar ----

    private val tabNames = arrayOf("Control", "Events", "Filter", "Settings")
    private val tabButtons = mutableListOf<Button>()
    private var currentTab = 0

    private fun createTabBar(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Color.parseColor("#283593"))

            for (i in tabNames.indices) {
                val btn = Button(this@MainActivity).apply {
                    text = tabNames[i]
                    setTextColor(Color.WHITE)
                    textSize = 13f
                    isAllCaps = false
                    setBackgroundColor(Color.TRANSPARENT)
                    layoutParams = LinearLayout.LayoutParams(0, dp(44), 1f)
                    setOnClickListener { switchTab(i) }
                }
                tabButtons.add(btn)
                addView(btn)
            }
        }
    }

    private fun switchTab(index: Int) {
        currentTab = index
        contentFrame.removeAllViews()
        val view = when (index) {
            0 -> controlView
            1 -> eventsView
            2 -> filterView
            3 -> settingsView
            else -> controlView
        }
        contentFrame.addView(view)

        tabButtons.forEachIndexed { i, btn ->
            if (i == index) {
                btn.setBackgroundColor(Color.parseColor("#3949ab"))
                btn.typeface = Typeface.DEFAULT_BOLD
            } else {
                btn.setBackgroundColor(Color.TRANSPARENT)
                btn.typeface = Typeface.DEFAULT
            }
        }
    }

    // ---- Control Tab ----

    private fun createControlTab(): ScrollView {
        val scroll = ScrollView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(12))
        }

        // Status section
        layout.addView(sectionTitle("Module Status"))
        statusText = TextView(this).apply {
            text = "Loading..."
            textSize = 13f
            setBackgroundColor(Color.parseColor("#f5f5f5"))
            setPadding(dp(12), dp(8), dp(12), dp(8))
            typeface = Typeface.MONOSPACE
        }
        layout.addView(statusText)
        layout.addView(spacer())

        // Action buttons
        layout.addView(sectionTitle("Actions"))

        val btnRow1 = buttonRow(
            actionButton("Enable", Color.parseColor("#2e7d32")) { vm.startMonitoring() },
            actionButton("Disable", Color.parseColor("#c62828")) { vm.stopMonitoring() }
        )
        layout.addView(btnRow1)

        val btnRow2 = buttonRow(
            actionButton("Poll Now", Color.parseColor("#1565c0")) { vm.pollOnce() },
            actionButton("Refresh", Color.parseColor("#4527a0")) { vm.refreshStatus() }
        )
        layout.addView(btnRow2)

        val btnRow3 = buttonRow(
            actionButton("Clear", Color.parseColor("#ef6c00")) { vm.clearEvents() },
            actionButton("Tier2 ON", Color.parseColor("#00838f")) { vm.setTier2(true) }
        )
        layout.addView(btnRow3)
        layout.addView(spacer())

        // Preset buttons
        layout.addView(sectionTitle("Presets"))
        for (preset in Preset.ALL_PRESETS) {
            layout.addView(presetButton(preset))
        }
        layout.addView(spacer())

        // Export buttons
        layout.addView(sectionTitle("Export"))
        val exportRow = buttonRow(
            actionButton("CSV", Color.parseColor("#558b2f")) { vm.exportCsv() },
            actionButton("JSON", Color.parseColor("#6a1b9a")) { vm.exportJson() }
        )
        layout.addView(exportRow)
        layout.addView(spacer())

        // Log
        layout.addView(sectionTitle("Log"))
        logText = TextView(this).apply {
            text = ""
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setBackgroundColor(Color.parseColor("#263238"))
            setTextColor(Color.parseColor("#b2ff59"))
            setPadding(dp(8), dp(8), dp(8), dp(8))
            maxLines = 200
            ellipsize = TextUtils.TruncateAt.END
        }
        layout.addView(logText)

        scroll.addView(layout)
        return scroll
    }

    // ---- Events Tab ----

    private fun createEventsTab(): LinearLayout {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(8), dp(8), dp(8), dp(8))
        }

        eventsCountText = TextView(this).apply {
            text = "Events: 0"
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(dp(8), dp(4), dp(8), dp(4))
        }
        layout.addView(eventsCountText)

        val scroll = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f
            )
        }
        eventsListLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        scroll.addView(eventsListLayout)
        layout.addView(scroll)

        return layout
    }

    // ---- Filter Tab ----

    private fun createFilterTab(): ScrollView {
        val scroll = ScrollView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(12))
        }

        layout.addView(sectionTitle("Syscall Filter"))
        layout.addView(TextView(this).apply {
            text = "Toggle individual syscalls to monitor:"
            textSize = 13f
            setPadding(0, 0, 0, dp(8))
        })

        // NR input row
        val inputRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        val nrInput = EditText(this).apply {
            hint = "NR (e.g. 56)"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        inputRow.addView(nrInput)
        inputRow.addView(Button(this).apply {
            text = "Add"
            setOnClickListener {
                val nr = nrInput.text.toString().toIntOrNull()
                if (nr != null) { vm.addNr(nr); toast("Added NR $nr") }
            }
        })
        inputRow.addView(Button(this).apply {
            text = "Remove"
            setOnClickListener {
                val nr = nrInput.text.toString().toIntOrNull()
                if (nr != null) { vm.removeNr(nr); toast("Removed NR $nr") }
            }
        })
        layout.addView(inputRow)
        layout.addView(spacer())

        // Syscall categories
        for (cat in StatusParser.SYSCALL_CATEGORIES) {
            layout.addView(sectionTitle(cat.name))
            for (entry in cat.entries) {
                layout.addView(createSyscallRow(entry))
            }
        }

        scroll.addView(layout)
        return scroll
    }

    private fun createSyscallRow(entry: StatusParser.SyscallEntry): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(4), dp(2), dp(4), dp(2))

            addView(TextView(this@MainActivity).apply {
                text = "${entry.nr}"
                textSize = 12f
                typeface = Typeface.MONOSPACE
                minWidth = dp(40)
            })
            addView(TextView(this@MainActivity).apply {
                text = entry.name
                textSize = 13f
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            })
            addView(Button(this@MainActivity).apply {
                text = "+"
                textSize = 11f
                minimumWidth = dp(40)
                minimumHeight = dp(32)
                setPadding(dp(4), 0, dp(4), 0)
                setOnClickListener { vm.addNr(entry.nr) }
            })
            addView(Button(this@MainActivity).apply {
                text = "-"
                textSize = 11f
                minimumWidth = dp(40)
                minimumHeight = dp(32)
                setPadding(dp(4), 0, dp(4), 0)
                setOnClickListener { vm.removeNr(entry.nr) }
            })
        }
    }

    // ---- Settings Tab ----

    private fun createSettingsTab(): ScrollView {
        val scroll = ScrollView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(12), dp(16), dp(12))
        }

        // SuperKey
        layout.addView(sectionTitle("SuperKey"))
        val keyInput = EditText(this).apply {
            hint = "Enter SuperKey"
            setText(KpmBridge.getSuperKey())
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                        android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        layout.addView(keyInput)
        layout.addView(Button(this).apply {
            text = "Update SuperKey"
            setOnClickListener {
                val key = keyInput.text.toString().trim()
                if (key.isNotEmpty()) {
                    vm.setSuperKey(key)
                    toast("SuperKey updated")
                }
            }
        })
        layout.addView(spacer())

        // App selection
        layout.addView(sectionTitle("Target App (UID Filter)"))
        layout.addView(TextView(this).apply {
            text = "Select an app to monitor only its syscalls:"
            textSize = 13f
        })
        layout.addView(Button(this).apply {
            text = "Select App..."
            setOnClickListener { showAppPicker() }
        })
        layout.addView(spacer())

        // Tier2
        layout.addView(sectionTitle("Tier2 Features"))
        layout.addView(featureRow("Caller Address", "Records LR register for each syscall") {
            vm.setTier2(true)
        })
        layout.addView(featureRow("FD Path Resolution", "Resolves file descriptor to path") {
            vm.setTier2(true)
        })
        layout.addView(featureRow("Clone Fn Capture", "Captures clone function pointer") {
            vm.setTier2(true)
        })
        layout.addView(spacer())

        // Info
        layout.addView(sectionTitle("About"))
        layout.addView(infoRow("Version", "8.3.0"))
        layout.addView(infoRow("Device", "Pixel 6 (oriole)"))
        layout.addView(infoRow("Kernel", "5.10.43 ARM64"))
        layout.addView(infoRow("Android", "12 (API 31)"))
        layout.addView(infoRow("Tier1 Hooks", "44 syscalls"))
        layout.addView(infoRow("Tier2 Hooks", "25 syscalls"))
        layout.addView(infoRow("Buffer", "1024 events / 128KB output"))

        scroll.addView(layout)
        return scroll
    }

    // ---- ViewModel Observers ----

    private fun observeViewModel() {
        vm.status.observe(this) { s ->
            statusText.text = buildString {
                append("Enabled:   ${s.enabled}\n")
                append("UID:       ${s.uid}\n")
                append("Tier2:     ${s.tier2}\n")
                append("Total:     ${s.eventsTotal}\n")
                append("Buffered:  ${s.eventsBuffered}\n")
                append("Tier1:     ${if (s.tier1Hooked) "hooked" else "off"}\n")
                append("Tier2:     ${if (s.tier2Hooked) "hooked" else "off"}\n")
                append("Version:   ${s.version}\n")
                append("NR Filter: ${s.nrFilter.take(60)}${if (s.nrFilter.length > 60) "..." else ""}")
            }
        }

        vm.events.observe(this) { events ->
            eventsCountText.text = "Events: ${events.size}"
            eventsListLayout.removeAllViews()
            // Show last 100 events in reverse order
            val recent = events.takeLast(100).reversed()
            for (ev in recent) {
                eventsListLayout.addView(createEventCard(ev))
            }
        }

        vm.log.observe(this) { text ->
            logText.text = text
        }
    }

    // ---- Event Card ----

    private fun createEventCard(ev: SvcEvent): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#fafafa"))
            setPadding(dp(8), dp(6), dp(8), dp(6))
            val lp = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            lp.bottomMargin = dp(4)
            layoutParams = lp

            // Header: seq, nr, name
            addView(TextView(this@MainActivity).apply {
                text = "#${ev.seq} NR=${ev.nr} ${ev.name} [pid=${ev.pid} uid=${ev.uid}]"
                textSize = 12f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(Color.parseColor("#1a237e"))
            })
            // Comm
            addView(TextView(this@MainActivity).apply {
                text = "comm=${ev.comm} ${ev.desc}"
                textSize = 11f
                typeface = Typeface.MONOSPACE
                maxLines = 2
                ellipsize = TextUtils.TruncateAt.END
            })
            // Extra info
            if (ev.caller != "0x0" && ev.caller.isNotEmpty()) {
                addView(TextView(this@MainActivity).apply {
                    text = "caller=${ev.caller} pc=${ev.pc}"
                    textSize = 10f
                    setTextColor(Color.parseColor("#666666"))
                })
            }
            if (ev.fdPath.isNotEmpty()) {
                addView(TextView(this@MainActivity).apply {
                    text = "fd_path=${ev.fdPath}"
                    textSize = 10f
                    setTextColor(Color.parseColor("#00695c"))
                })
            }
        }
    }

    // ---- App Picker Dialog ----

    private fun showAppPicker() {
        val apps = AppResolver.getAllApps(this)
        val names = apps.map { it.toString() }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle("Select Target App")
            .setItems(names) { _, which ->
                val app = apps[which]
                vm.selectApp(app)
                toast("Selected: ${app.label} (uid=${app.uid})")
            }
            .setNegativeButton("Clear Filter") { _, _ ->
                vm.selectApp(null)
                toast("UID filter cleared")
            }
            .show()
    }

    // ---- UI Helpers ----

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    private fun toast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    }

    private fun sectionTitle(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 16f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.parseColor("#1a237e"))
            setPadding(0, dp(8), 0, dp(4))
        }
    }

    private fun spacer(): View {
        return View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(12)
            )
        }
    }

    private fun actionButton(text: String, bgColor: Int, onClick: () -> Unit): Button {
        return Button(this).apply {
            this.text = text
            setTextColor(Color.WHITE)
            setBackgroundColor(bgColor)
            isAllCaps = false
            setOnClickListener { onClick() }
        }
    }

    private fun buttonRow(vararg buttons: Button): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(4), 0, dp(4))
            for (btn in buttons) {
                val lp = LinearLayout.LayoutParams(0, dp(44), 1f)
                lp.marginEnd = dp(8)
                btn.layoutParams = lp
                addView(btn)
            }
        }
    }

    private fun presetButton(preset: Preset): Button {
        return Button(this).apply {
            text = "${preset.id}. ${preset.name} - ${preset.description}"
            textSize = 12f
            isAllCaps = false
            gravity = Gravity.START or Gravity.CENTER_VERTICAL
            setPadding(dp(12), dp(4), dp(12), dp(4))
            setOnClickListener {
                vm.selectPreset(preset)
                toast("Preset: ${preset.name}")
            }
        }
    }

    private fun featureRow(title: String, desc: String, onEnable: () -> Unit): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(4), dp(4), dp(4), dp(4))

            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                addView(TextView(this@MainActivity).apply {
                    text = title
                    textSize = 14f
                    typeface = Typeface.DEFAULT_BOLD
                    setTextColor(Color.parseColor("#00838f"))
                })
                addView(TextView(this@MainActivity).apply {
                    text = desc
                    textSize = 11f
                    setTextColor(Color.GRAY)
                })
            })
        }
    }

    private fun infoRow(label: String, value: String): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(4), dp(2), dp(4), dp(2))
            addView(TextView(this@MainActivity).apply {
                text = "$label:"
                textSize = 13f
                typeface = Typeface.DEFAULT_BOLD
                minWidth = dp(100)
            })
            addView(TextView(this@MainActivity).apply {
                text = value
                textSize = 13f
            })
        }
    }
}
