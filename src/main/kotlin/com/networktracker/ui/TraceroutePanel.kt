package com.networktracker.ui

import com.networktracker.monitor.Diagnoser
import com.networktracker.net.HopStats
import com.networktracker.net.TraceSession
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.BorderLayout
import java.awt.Component
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Graphics
import java.awt.geom.RoundRectangle2D
import java.net.InetAddress
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingConstants
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer

/** Continuous (MTR-style) traceroute: shows loss and latency for every hop along the path. */
class TraceroutePanel(private val scope: CoroutineScope) : JPanel(BorderLayout(0, 12)) {
    private val hostField = JTextField(24).apply {
        putClientProperty("JTextField.placeholderText", "Host or IP address, e.g. 8.8.8.8")
        putClientProperty("JTextField.showClearButton", true)
    }
    private val startButton = JButton("Start trace")
    private val namesBox = JCheckBox("Resolve hostnames", true)
    private val statusLabel = JLabel(" ")
    private val analysis = JTextArea().apply {
        isEditable = false; lineWrap = true; wrapStyleWord = true; isOpaque = false
        border = null
        rows = 2
    }
    private val model = HopModel()
    private var job: Job? = null
    private var session: TraceSession? = null

    init {
        isOpaque = false
        border = BorderFactory.createEmptyBorder(12, 12, 12, 12)
        startButton.putClientProperty("JButton.buttonType", "default")
        startButton.addActionListener { if (job?.isActive == true) stop() else start(hostField.text) }
        hostField.addActionListener { start(hostField.text) }

        val bar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            isOpaque = false
            add(hostField); add(startButton); add(namesBox); add(statusLabel)
        }
        add(bar, BorderLayout.NORTH)

        val table = object : JTable(model) {
            override fun updateUI() { super.updateUI(); rowHeight = 28 }
        }.apply {
            showVerticalLines = false
            fillsViewportHeight = true
            tableHeader.reorderingAllowed = false
            setDefaultRenderer(Any::class.java, HopRenderer())
            listOf(44, 130, 260, 70, 60, 70, 70, 70, 70, 70, 200).forEachIndexed { i, w -> columnModel.getColumn(i).preferredWidth = w }
        }
        val scroll = JScrollPane(table).apply { border = BorderFactory.createEmptyBorder() }
        add(Card("Route", scroll), BorderLayout.CENTER)

        val help = JLabel("<html><span style='color:${Theme.hex(Theme.muted)}'>Tip: loss that appears at one hop but not at the hops after it is " +
            "just that router ignoring ping (ICMP rate-limiting). Real loss continues all the way to the destination.</span></html>")
        val bottom = JPanel(BorderLayout(0, 6)).apply {
            isOpaque = false
            add(analysis, BorderLayout.CENTER)
            add(help, BorderLayout.SOUTH)
        }
        add(Card("Analysis", bottom), BorderLayout.SOUTH)
        analysis.text = "Enter a host and press Start trace. Traces run continuously so intermittent problems show up."
    }

    fun traceTo(host: String) {
        hostField.text = host
        start(host)
    }

    private fun start(input: String) {
        val host = input.trim()
        if (host.isEmpty()) return
        stop()
        startButton.text = "Stop"
        statusLabel.text = "Resolving $host…"
        job = scope.launch {
            val addr = withContext(Dispatchers.IO) { runCatching { InetAddress.getByName(host) }.getOrNull() }
            if (addr == null) {
                statusLabel.text = "Could not resolve \"$host\""
                startButton.text = "Start trace"
                return@launch
            }
            val s = TraceSession(addr)
            session = s
            statusLabel.text = "Discovering route to ${addr.hostAddress}…"
            s.discover()
            model.hops = s.hops
            analysis.text = s.analyze()
            if (namesBox.isSelected) launch { s.resolveNames(); model.fireTableDataChanged() }
            var rounds = 1
            while (isActive) {
                statusLabel.text = "Tracing ${addr.hostAddress} · ${s.hops.size} hops · round $rounds"
                delay(1000)
                s.round()
                rounds++
                model.fireTableRowsUpdated(0, (s.hops.size - 1).coerceAtLeast(0))
                analysis.text = s.analyze()
                if (namesBox.isSelected && rounds % 10 == 0) launch { s.resolveNames(); model.fireTableDataChanged() }
            }
        }
        job?.invokeOnCompletion {
            javax.swing.SwingUtilities.invokeLater { if (job?.isActive != true) startButton.text = "Start trace" }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
        startButton.text = "Start trace"
        if (session != null) statusLabel.text = "Stopped"
    }

    private class HopModel : AbstractTableModel() {
        var hops: List<HopStats> = emptyList()
            set(v) { field = v; fireTableDataChanged() }
        private val cols = listOf("Hop", "Address", "Hostname", "Loss", "Sent", "Last", "Avg", "Best", "Worst", "Jitter", "Latency")
        override fun getRowCount() = hops.size
        override fun getColumnCount() = cols.size
        override fun getColumnName(c: Int) = cols[c]
        override fun getValueAt(r: Int, c: Int): Any = hops[r]
    }

    private inner class HopRenderer : DefaultTableCellRenderer() {
        private var bar: HopStats? = null

        override fun getTableCellRendererComponent(t: JTable, v: Any?, sel: Boolean, f: Boolean, r: Int, c: Int): Component {
            super.getTableCellRendererComponent(t, "", sel, false, r, c)
            val h = v as HopStats
            bar = if (c == 10) h else null
            border = BorderFactory.createEmptyBorder(0, 8, 0, 10)
            foreground = if (sel) t.selectionForeground else Theme.foreground
            font = t.font
            horizontalAlignment = if (c in 3..9 || c == 0) SwingConstants.RIGHT else SwingConstants.LEFT
            text = when (c) {
                0 -> h.ttl.toString()
                1 -> { font = t.font.deriveFont(Font.BOLD); h.address ?: "* * *" }
                2 -> h.hostname ?: ""
                3 -> {
                    if (!sel && h.sent > 0) foreground = when {
                        h.lossPercent >= 20 -> Theme.bad; h.lossPercent > 0 -> Theme.warn; else -> Theme.good
                    }
                    Diagnoser.pct(h.lossPercent)
                }
                4 -> h.sent.toString()
                5 -> Diagnoser.ms(h.last)
                6 -> Diagnoser.ms(h.average)
                7 -> Diagnoser.ms(h.best)
                8 -> Diagnoser.ms(h.worst)
                9 -> Diagnoser.ms(h.jitter)
                else -> ""
            }
            if (h.address == null && c == 1) foreground = Theme.muted
            return this
        }

        override fun paintComponent(g: Graphics) {
            super.paintComponent(g)
            val h = bar ?: return
            if (h.received == 0) return
            val maxWorst = model.hops.maxOfOrNull { if (it.worst.isNaN()) 0.0 else it.worst }?.coerceAtLeast(1.0) ?: return
            val g2 = Theme.smooth(g)
            val pad = 8.0
            val w = width - pad * 2
            val y = height / 2.0 - 4
            fun x(v: Double) = pad + (v / maxWorst) * w
            g2.color = Theme.track
            g2.fill(RoundRectangle2D.Double(pad, y, w, 8.0, 8.0, 8.0))
            // best..worst range, with a tick at the average
            g2.color = Theme.alpha(Theme.series(0), 0.35)
            g2.fill(RoundRectangle2D.Double(x(h.best), y, (x(h.worst) - x(h.best)).coerceAtLeast(3.0), 8.0, 8.0, 8.0))
            g2.color = if (h.lossPercent >= 20) Theme.bad else Theme.series(0)
            g2.fill(RoundRectangle2D.Double(x(h.average) - 2, y - 2, 4.0, 12.0, 3.0, 3.0))
            g2.dispose()
        }
    }
}
