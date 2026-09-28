package com.networktracker.ui

import com.networktracker.monitor.MonitorEngine
import com.networktracker.monitor.NetEvent
import com.networktracker.monitor.Severity
import kotlinx.coroutines.launch
import java.awt.BorderLayout
import java.awt.Component
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.GridLayout
import java.awt.Insets
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JProgressBar
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.SwingConstants
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer

class EventsPanel(private val engine: MonitorEngine) : JPanel(BorderLayout(0, 10)) {
    private val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
    private val filter = JComboBox(arrayOf("All events", "Warnings and errors", "Errors only"))
    private val countLabel = JLabel()
    private var rows: List<NetEvent> = emptyList()
    private val model = object : AbstractTableModel() {
        val cols = listOf("Time", "Severity", "Source", "Message")
        override fun getRowCount() = rows.size
        override fun getColumnCount() = 4
        override fun getColumnName(c: Int) = cols[c]
        override fun getValueAt(r: Int, c: Int): Any = rows[r]
    }

    init {
        isOpaque = false
        border = BorderFactory.createEmptyBorder(12, 12, 12, 12)
        filter.addActionListener { refresh() }
        val clear = JButton("Clear log").apply {
            addActionListener { engine.events.clear(); refresh() }
        }
        add(JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            isOpaque = false
            add(JLabel("Show:")); add(filter); add(clear); add(countLabel)
        }, BorderLayout.NORTH)

        val table = object : JTable(model) {
            override fun updateUI() { super.updateUI(); rowHeight = 28 }
        }.apply {
            showVerticalLines = false
            fillsViewportHeight = true
            tableHeader.reorderingAllowed = false
            listOf(160, 110, 110, 700).forEachIndexed { i, w -> columnModel.getColumn(i).preferredWidth = w }
            setDefaultRenderer(Any::class.java, object : DefaultTableCellRenderer() {
                override fun getTableCellRendererComponent(t: JTable, v: Any?, sel: Boolean, f: Boolean, r: Int, c: Int): Component {
                    super.getTableCellRendererComponent(t, "", sel, false, r, c)
                    val e = v as NetEvent
                    border = BorderFactory.createEmptyBorder(0, 8, 0, 8)
                    icon = null
                    foreground = if (sel) t.selectionForeground else Theme.foreground
                    font = t.font
                    text = when (c) {
                        0 -> fmt.format(Date(e.time))
                        1 -> {
                            icon = DotIcon({ Theme.severity(e.severity) })
                            iconTextGap = 7
                            if (!sel) foreground = Theme.severity(e.severity)
                            font = t.font.deriveFont(Font.BOLD)
                            e.severity.name.lowercase().replaceFirstChar { it.uppercase() }
                        }
                        2 -> e.source
                        else -> e.message
                    }
                    toolTipText = if (c == 3) e.message else null
                    return this
                }
            })
        }
        add(Card("Event log", JScrollPane(table).apply { border = BorderFactory.createEmptyBorder() }), BorderLayout.CENTER)
        engine.onEvent { refresh() }
        refresh()
    }

    fun refresh() {
        val min = when (filter.selectedIndex) { 1 -> 1; 2 -> 2; else -> 0 }
        fun rank(s: Severity) = when (s) { Severity.ERROR -> 2; Severity.WARNING -> 1; else -> 0 }
        rows = engine.events.filter { rank(it.severity) >= min }.asReversed()
        model.fireTableDataChanged()
        val errors = engine.events.count { it.severity == Severity.ERROR }
        val warnings = engine.events.count { it.severity == Severity.WARNING }
        countLabel.text = "   ${engine.events.size} events · $errors errors · $warnings warnings"
    }
}

class NetworkInfoPanel(private val engine: MonitorEngine) : JPanel(BorderLayout(0, 12)) {
    private val connection = KeyValueGrid()
    private val routing = KeyValueGrid()
    private val wifiGrid = KeyValueGrid()
    private val signalBar = JProgressBar(0, 100).apply { isStringPainted = true; preferredSize = java.awt.Dimension(200, 22) }
    private val signalChart = SignalChart(engine)

    init {
        isOpaque = false
        border = BorderFactory.createEmptyBorder(12, 12, 12, 12)
        val refresh = JButton("Refresh").apply {
            addActionListener { engine.scope.launch { engine.refreshInfo() } }
        }
        add(JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            isOpaque = false
            add(refresh)
            add(JLabel("Information refreshes automatically every 30 seconds while monitoring; Wi-Fi every 5 seconds."))
        }, BorderLayout.NORTH)

        val wifiPanel = JPanel(BorderLayout(0, 8)).apply {
            isOpaque = false
            add(signalBar, BorderLayout.NORTH)
            add(wifiGrid, BorderLayout.CENTER)
        }
        val top = JPanel(GridLayout(1, 3, 12, 0)).apply {
            isOpaque = false
            add(Card("Connection", connection))
            add(Card("Routing & DNS", routing))
            add(Card("Wi-Fi", wifiPanel))
        }
        val body = JPanel(BorderLayout(0, 12)).apply {
            isOpaque = false
            add(top, BorderLayout.NORTH)
            add(Card("Wi-Fi signal history  (orange lines = roamed to another access point)", signalChart), BorderLayout.CENTER)
        }
        add(body, BorderLayout.CENTER)
        engine.onChange { refresh() }
        refresh()
    }

    fun refresh() {
        val a = engine.adapter
        connection.set(listOf(
            "Adapter" to (a?.displayName ?: "—"),
            "Type" to (a?.let { if (it.isWireless || engine.wifi != null) "Wi-Fi" else "Wired (Ethernet)" } ?: "—"),
            "Local IP" to (a?.let { it.localAddress + (it.prefixLength?.let { p -> "/$p" } ?: "") } ?: "—"),
            "MAC" to (a?.mac ?: "—"),
            "MTU" to (a?.mtu?.toString() ?: "—"),
        ))
        routing.set(listOf(
            "Default gateway" to (engine.gateway ?: "—"),
            "ISP edge router" to (engine.ispHop ?: "not detected"),
            "DNS servers" to engine.dnsServers.joinToString(", ").ifEmpty { "—" },
            "Probe interval" to "${engine.intervalMs} ms",
            "Probe timeout" to "${engine.timeoutMs} ms",
        ))
        val w = engine.wifi
        if (w == null) {
            signalBar.value = 0
            signalBar.string = "Not connected via Wi-Fi"
            wifiGrid.set(listOf("Status" to "No active Wi-Fi connection"))
        } else {
            val s = w.signalPercent ?: 0
            signalBar.value = s
            signalBar.string = "Signal $s%  ·  ≈ ${w.approxDbm} dBm"
            signalBar.foreground = when { s < 40 -> Theme.bad; s < 60 -> Theme.warn; else -> Theme.good }
            wifiGrid.set(listOf(
                "SSID" to (w.ssid ?: "—"),
                "Access point" to (w.bssid ?: "—"),
                "Band / channel" to listOfNotNull(w.band, w.channel?.let { "ch $it" }).joinToString(" · ").ifEmpty { "—" },
                "Standard" to (w.radioType ?: "—"),
                "Link rate" to "↓ ${w.receiveMbps?.toInt() ?: "—"} Mbps  ↑ ${w.transmitMbps?.toInt() ?: "—"} Mbps",
            ))
        }
        signalChart.repaint()
    }

    fun repaintChart() = signalChart.repaint()
}

class KeyValueGrid : JPanel(GridBagLayout()) {
    init { isOpaque = false }

    fun set(rows: List<Pair<String, String>>) {
        removeAll()
        rows.forEachIndexed { i, (k, v) ->
            val c = GridBagConstraints().apply { gridy = i; anchor = GridBagConstraints.WEST; insets = Insets(3, 0, 3, 14) }
            add(JLabel(k).apply { foreground = Theme.muted }, c.apply { gridx = 0; weightx = 0.0 })
            add(JLabel(v).apply { horizontalAlignment = SwingConstants.LEFT; font = Theme.font(Font.BOLD) },
                c.clone().let { (it as GridBagConstraints).apply { gridx = 1; weightx = 1.0; fill = GridBagConstraints.HORIZONTAL; insets = Insets(3, 0, 3, 0) } })
        }
        add(JPanel().apply { isOpaque = false }, GridBagConstraints().apply { gridy = rows.size; weighty = 1.0 })
        revalidate(); repaint()
    }
}
