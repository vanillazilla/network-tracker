package com.networktracker.ui

import com.formdev.flatlaf.FlatLaf
import com.formdev.flatlaf.themes.FlatMacDarkLaf
import com.formdev.flatlaf.themes.FlatMacLightLaf
import com.networktracker.monitor.Diagnoser
import com.networktracker.monitor.Health
import com.networktracker.monitor.MonitorEngine
import com.networktracker.monitor.Target
import com.networktracker.monitor.TargetRole
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.ImageIcon
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JFileChooser
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTabbedPane
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.Timer
import javax.swing.filechooser.FileNameExtensionFilter

class MainWindow(private val engine: MonitorEngine) : JFrame("Network Tracker") {
    private val state = ChartState(engine)

    private val intervals = listOf(500, 1000, 2000, 5000, 10000)
    private val timeouts = listOf(500, 1000, 2000, 3000)
    private val windows = listOf<Pair<String, Long?>>(
        "Last 1 min" to 60_000L, "Last 5 min" to 300_000L, "Last 15 min" to 900_000L,
        "Last 1 hour" to 3_600_000L, "Last 6 hours" to 21_600_000L, "Whole session" to null,
    )

    // Header
    private val statusLabel = JLabel()
    private val startButton = JButton("Start monitoring")

    // Toolbar
    private val hostField = JTextField(26)
    private val intervalBox = JComboBox(intervals.map { if (it < 1000) "Every $it ms" else "Every ${it / 1000} s" }.toTypedArray())
    private val timeoutBox = JComboBox(timeouts.map { "Timeout ${if (it < 1000) "$it ms" else "${it / 1000} s"}" }.toTypedArray())
    private val windowBox = JComboBox(windows.map { it.first }.toTypedArray())

    // Dashboard
    private val path = PathDiagram()
    private val chart = LatencyChart(engine, state)
    private val timeline = TimelineStrip(engine, state)
    private val diagnosis = DiagnosisView()
    private val tabs = JTabbedPane()
    private val tracePanel = TraceroutePanel(engine.scope)
    private val table = TargetsTable(engine, state) { t -> tracePanel.traceTo(t.displayAddress); tabs.selectedIndex = 1 }
    private val eventsPanel = EventsPanel(engine)
    private val infoPanel = NetworkInfoPanel(engine)
    private val trafficPanel = com.networktracker.ui.traffic.TrafficPanel(engine)
    private var unseenProblems = 0

    init {
        defaultCloseOperation = DISPOSE_ON_CLOSE
        iconImages = Theme.appIcons()
        minimumSize = Dimension(1100, 720)
        restoreBounds()

        intervalBox.selectedIndex = Settings.intervalIndex.coerceIn(0, intervals.size - 1)
        timeoutBox.selectedIndex = Settings.timeoutIndex.coerceIn(0, timeouts.size - 1)
        windowBox.selectedIndex = Settings.windowIndex.coerceIn(0, windows.size - 1)
        applySettings()

        contentPane = JPanel(BorderLayout()).apply {
            add(JPanel(BorderLayout()).apply {
                isOpaque = false
                add(buildHeader(), BorderLayout.NORTH)
                add(buildToolbar(), BorderLayout.SOUTH)
            }, BorderLayout.NORTH)
            add(buildTabs(), BorderLayout.CENTER)
        }

        engine.onTick { refreshDashboard() }
        engine.onChange {
            table.tableModel.refresh()
            timeline.revalidate()
            refreshDashboard()
            updateHeader()
        }
        engine.onEvent { e ->
            if (tabs.selectedIndex != 2 && (e.severity == com.networktracker.monitor.Severity.ERROR || e.severity == com.networktracker.monitor.Severity.WARNING)) {
                unseenProblems++
                tabs.setTitleAt(2, "Events ($unseenProblems)")
            }
        }
        state.listeners += { chart.repaint(); timeline.repaint(); table.repaint() }
        Timer(1000) { updateHeader(); if (!engine.running) chart.repaint() }.start()

        addWindowListener(object : WindowAdapter() {
            override fun windowClosed(e: WindowEvent) {
                saveBounds()
                engine.stop()
                tracePanel.stop()
                trafficPanel.shutdown()
                System.exit(0)
            }
        })

        updateHeader()
        refreshDashboard()
    }

    // ---------------------------------------------------------------- layout

    private fun buildHeader(): JComponent {
        val title = JLabel("Network Tracker").apply { font = Theme.font(Font.BOLD, 6f) }
        val subtitle = JLabel("Find out whether connection problems come from your PC, your router, your ISP, or the remote host")
            .apply { foreground = Theme.muted }
        val titles = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(title); add(Box.createVerticalStrut(2)); add(subtitle)
        }
        val logo = JLabel(ImageIcon(Theme.appIcons()[4].getScaledInstance(40, 40, java.awt.Image.SCALE_SMOOTH)))
        val left = JPanel(FlowLayout(FlowLayout.LEFT, 12, 0)).apply { isOpaque = false; add(logo); add(titles) }

        startButton.putClientProperty("JButton.buttonType", "default")
        startButton.font = Theme.font(Font.BOLD, 1f)
        startButton.preferredSize = Dimension(170, 38)
        startButton.addActionListener { if (engine.running) engine.stop() else engine.start() }
        statusLabel.font = Theme.font(Font.BOLD)
        val right = JPanel(FlowLayout(FlowLayout.RIGHT, 14, 0)).apply { isOpaque = false; add(statusLabel); add(startButton) }

        return JPanel(BorderLayout()).apply {
            border = BorderFactory.createEmptyBorder(14, 16, 10, 16)
            add(left, BorderLayout.WEST)
            add(right, BorderLayout.EAST)
        }
    }

    private fun buildToolbar(): JComponent {
        hostField.putClientProperty("JTextField.placeholderText", "IP address or hostname to ping, e.g. 192.168.1.20 or example.com")
        hostField.putClientProperty("JTextField.showClearButton", true)
        hostField.addActionListener { addHost() }
        val addButton = JButton("Add & ping").apply { addActionListener { addHost() } }

        intervalBox.addActionListener { Settings.intervalIndex = intervalBox.selectedIndex; applySettings() }
        timeoutBox.addActionListener { Settings.timeoutIndex = timeoutBox.selectedIndex; applySettings() }
        windowBox.addActionListener {
            Settings.windowIndex = windowBox.selectedIndex
            state.windowMs = windows[windowBox.selectedIndex].second
            state.changed(); refreshDashboard()
        }
        windowBox.toolTipText = "Time range shown in the chart and used for statistics and diagnosis"

        val detect = JButton("Re-detect network").apply {
            toolTipText = "Detect router, ISP edge router and DNS server again"
            addActionListener { engine.autoDetect() }
        }
        val clear = JButton("Clear data").apply {
            addActionListener {
                if (JOptionPane.showConfirmDialog(this@MainWindow, "Discard all collected measurements?", "Clear data",
                        JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) engine.clearData()
            }
        }
        val export = JButton("Export ▾")
        export.addActionListener {
            JPopupMenu().apply {
                add(JMenuItem("Save diagnostic report (.txt)…").apply { addActionListener { saveReport() } })
                add(JMenuItem("Copy report to clipboard").apply {
                    addActionListener {
                        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(report()), null)
                        flash("Report copied to clipboard")
                    }
                })
                add(JMenuItem("Export raw measurements (.csv)…").apply { addActionListener { saveCsv() } })
            }.show(export, 0, export.height)
        }
        val theme = JButton(if (Settings.dark) "Light theme" else "Dark theme").apply {
            toolTipText = "Toggle light/dark theme"
            addActionListener {
                Settings.dark = !Settings.dark
                text = if (Settings.dark) "Light theme" else "Dark theme"
                if (Settings.dark) FlatMacDarkLaf.setup() else FlatMacLightLaf.setup()
                FlatLaf.updateUI()
                infoPanel.refresh(); refreshDashboard()
            }
        }

        val left = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply { isOpaque = false; add(hostField); add(addButton) }
        val right = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 0)).apply {
            isOpaque = false
            add(intervalBox); add(timeoutBox); add(windowBox); add(detect); add(clear); add(export); add(theme)
        }
        return JPanel(BorderLayout()).apply {
            border = BorderFactory.createEmptyBorder(0, 10, 8, 10)
            add(left, BorderLayout.WEST)
            add(right, BorderLayout.EAST)
        }
    }

    private fun buildTabs(): JComponent {
        tabs.putClientProperty("JTabbedPane.tabType", "underlined")
        tabs.putClientProperty("JTabbedPane.tabAreaInsets", java.awt.Insets(0, 10, 0, 10))
        tabs.addTab("Dashboard", buildDashboard())
        tabs.addTab("Traceroute", tracePanel)
        tabs.addTab("Events", eventsPanel)
        tabs.addTab("Network Info", infoPanel)
        tabs.addTab("Traffic", trafficPanel)
        tabs.addChangeListener {
            if (tabs.selectedIndex == 2) { unseenProblems = 0; tabs.setTitleAt(2, "Events") }
            if (tabs.selectedIndex == 3) infoPanel.repaintChart()
        }
        return tabs
    }

    private fun buildDashboard(): JComponent {
        val legendHint = JLabel("Click a legend entry to show/hide · hover for values").apply {
            foreground = Theme.muted; font = Theme.font(Font.PLAIN, -1f)
        }
        val timelineHeader = JLabel("Timeline   ● replied   ● slow   ● lost").apply {
            font = Theme.font(Font.PLAIN, -1f)
            foreground = Theme.muted
            border = BorderFactory.createEmptyBorder(8, ChartState.LEFT, 4, 0)
            text = "<html>Timeline &nbsp;&nbsp;<span style='color:${Theme.hex(Theme.good)}'>■</span> replied &nbsp;" +
                "<span style='color:${Theme.hex(Theme.warn)}'>■</span> slow &nbsp;<span style='color:${Theme.hex(Theme.bad)}'>■</span> lost" +
                " &nbsp;— red that lines up across rows shows where a drop started</html>"
        }
        val chartBody = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(chart, BorderLayout.CENTER)
            add(JPanel(BorderLayout()).apply {
                isOpaque = false
                add(timelineHeader, BorderLayout.NORTH)
                add(timeline, BorderLayout.CENTER)
            }, BorderLayout.SOUTH)
        }
        val chartCard = Card("Latency", chartBody, legendHint)
        val tableScroll = JScrollPane(table).apply { border = BorderFactory.createEmptyBorder() }
        val tableCard = Card("Targets", tableScroll, JLabel("Right-click a row for options · double-click to traceroute").apply {
            foreground = Theme.muted; font = Theme.font(Font.PLAIN, -1f)
        })
        val left = split(JSplitPane.VERTICAL_SPLIT, chartCard, tableCard, 0.62)
        val diagCard = Card("Diagnosis", diagnosis).apply { preferredSize = Dimension(380, 400); minimumSize = Dimension(300, 200) }
        val main = split(JSplitPane.HORIZONTAL_SPLIT, left, diagCard, 0.7)
        return JPanel(BorderLayout(0, 12)).apply {
            border = BorderFactory.createEmptyBorder(12, 12, 12, 12)
            add(path, BorderLayout.NORTH)
            add(main, BorderLayout.CENTER)
        }
    }

    private fun split(orientation: Int, a: JComponent, b: JComponent, weight: Double) = JSplitPane(orientation, a, b).apply {
        resizeWeight = weight
        dividerSize = 12
        border = null
        isOpaque = false
        isContinuousLayout = true
        a.minimumSize = Dimension(200, 150)
    }

    // ---------------------------------------------------------------- behaviour

    private fun applySettings() {
        engine.intervalMs = intervals[intervalBox.selectedIndex]
        engine.timeoutMs = timeouts[timeoutBox.selectedIndex].coerceAtMost(maxOf(engine.intervalMs, 500) * 3)
        state.windowMs = windows[windowBox.selectedIndex].second
        infoPanel.refresh()
    }

    private fun addHost() {
        val host = hostField.text.trim().removePrefix("http://").removePrefix("https://").substringBefore('/')
        if (host.isEmpty()) return
        if (host.any { it.isWhitespace() }) {
            JOptionPane.showMessageDialog(this, "\"$host\" is not a valid host name or IP address.", "Invalid host", JOptionPane.WARNING_MESSAGE)
            return
        }
        engine.addTarget(Target(TargetRole.CUSTOM, host, host))
        Settings.customTargets = (Settings.customTargets + host).distinct()
        hostField.text = ""
        if (!engine.running) engine.start()
    }

    fun loadSavedTargets() {
        Settings.customTargets.forEach { engine.addTarget(Target(TargetRole.CUSTOM, it, it)) }
        // Forget removed custom targets.
        engine.onChange {
            val current = engine.targets.filter { it.role == TargetRole.CUSTOM }.map { it.host }
            if (current != Settings.customTargets) Settings.customTargets = current
        }
    }

    private fun refreshDashboard() {
        table.tableModel.refresh()
        val d = Diagnoser.diagnose(engine.targets, state.statsFrom(), engine.wifi, engine.adapter)
        path.tiers = d.path
        diagnosis.show(d)
        chart.repaint()
        timeline.repaint()
        if (timeline.preferredSize.height != timeline.height) timeline.revalidate()
        title = when (d.health) {
            Health.BAD -> "Network Tracker — ${d.headline}"
            else -> "Network Tracker"
        }
    }

    private var flashText: String? = null
    private var flashUntil = 0L

    private fun flash(msg: String) {
        flashText = msg; flashUntil = System.currentTimeMillis() + 2500
        updateHeader()
    }

    private fun updateHeader() {
        val now = System.currentTimeMillis()
        if (flashText != null && now < flashUntil) {
            statusLabel.icon = DotIcon({ Theme.accent }, 10)
            statusLabel.text = flashText
            return
        }
        when {
            engine.detecting -> {
                statusLabel.icon = DotIcon({ Theme.warn }, 10)
                statusLabel.text = "Detecting network…"
            }
            engine.running -> {
                val secs = (now - engine.startedAt) / 1000
                statusLabel.icon = DotIcon({ if ((secs % 2) == 0L) Theme.good else Theme.alpha(Theme.good, 0.45) }, 10)
                statusLabel.text = "Monitoring  %02d:%02d:%02d".format(secs / 3600, secs / 60 % 60, secs % 60)
            }
            else -> {
                statusLabel.icon = DotIcon({ Theme.unknown }, 10)
                statusLabel.text = "Idle"
            }
        }
        startButton.text = if (engine.running) "Stop monitoring" else "Start monitoring"
        startButton.putClientProperty("JButton.buttonType", if (engine.running) null else "default")
    }

    private fun report() = Exporter.report(engine, state.statsFrom(), windows[windowBox.selectedIndex].first)

    private fun chooseFile(name: String, ext: String, desc: String): File? {
        val fc = JFileChooser().apply {
            selectedFile = File(System.getProperty("user.home"), name)
            fileFilter = FileNameExtensionFilter(desc, ext)
        }
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return null
        return fc.selectedFile.let { if (it.extension.equals(ext, true)) it else File(it.path + ".$ext") }
    }

    private fun stamp() = SimpleDateFormat("yyyyMMdd-HHmmss").format(Date())

    private fun saveReport() {
        val f = chooseFile("network-report-${stamp()}.txt", "txt", "Text report") ?: return
        runCatching { f.writeText(report()) }
            .onSuccess { flash("Report saved to ${f.name}") }
            .onFailure { JOptionPane.showMessageDialog(this, "Could not save: ${it.message}", "Error", JOptionPane.ERROR_MESSAGE) }
    }

    private fun saveCsv() {
        val f = chooseFile("network-samples-${stamp()}.csv", "csv", "CSV file") ?: return
        runCatching { Exporter.writeCsv(engine, f) }
            .onSuccess { flash("Measurements saved to ${f.name}") }
            .onFailure { JOptionPane.showMessageDialog(this, "Could not save: ${it.message}", "Error", JOptionPane.ERROR_MESSAGE) }
    }

    private fun restoreBounds() {
        val parts = Settings.bounds?.split(',')?.mapNotNull { it.toIntOrNull() }
        if (parts != null && parts.size == 4) {
            setBounds(parts[0], parts[1], parts[2], parts[3])
            // Ignore saved bounds that are off-screen (e.g. a monitor was disconnected).
            val screens = java.awt.GraphicsEnvironment.getLocalGraphicsEnvironment().screenDevices
            if (screens.none { it.defaultConfiguration.bounds.intersects(bounds) }) setLocationRelativeTo(null)
        } else {
            size = Dimension(1440, 900)
            setLocationRelativeTo(null)
        }
    }

    private fun saveBounds() {
        if (extendedState and MAXIMIZED_BOTH == 0) Settings.bounds = "$x,$y,$width,$height"
    }

    companion object {
        fun launch(engine: MonitorEngine) = SwingUtilities.invokeLater {
            val w = MainWindow(engine)
            w.isVisible = true
            w.loadSavedTargets()
            engine.autoDetect { if (!engine.running) engine.start() }
        }
    }
}
