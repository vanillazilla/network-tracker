package com.networktracker.ui

import com.networktracker.monitor.Diagnoser
import com.networktracker.monitor.Health
import com.networktracker.monitor.MonitorEngine
import com.networktracker.monitor.ProbeKind
import com.networktracker.monitor.Summary
import com.networktracker.monitor.Target
import com.networktracker.monitor.TargetRole
import java.awt.Component
import java.awt.Font
import java.awt.Graphics
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.geom.RoundRectangle2D
import javax.swing.JMenuItem
import javax.swing.JPopupMenu
import javax.swing.JTable
import javax.swing.ListSelectionModel
import javax.swing.SwingConstants
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer

class TargetsTableModel(private val engine: MonitorEngine, private val state: ChartState) : AbstractTableModel() {
    private val columns = listOf("", "Status", "Role", "Name", "Address", "Last", "Avg", "Min", "Max", "Jitter", "Loss", "Sent", "Lost")
    var rows: List<Pair<Target, Summary>> = emptyList(); private set

    fun refresh() {
        val from = state.statsFrom()
        val newRows = engine.targets.map { it to it.summary(from) }
        val structural = newRows.map { it.first.id } != rows.map { it.first.id }
        rows = newRows
        if (structural) fireTableDataChanged() else if (rows.isNotEmpty()) fireTableRowsUpdated(0, rows.size - 1)
    }

    override fun getRowCount() = rows.size
    override fun getColumnCount() = columns.size
    override fun getColumnName(c: Int) = columns[c]
    override fun getValueAt(r: Int, c: Int): Any? = rows[r]

    fun health(t: Target, s: Summary): Health {
        if (s.sent == 0) return Health.UNKNOWN
        if (t.consecutiveLost >= MonitorEngine.OUTAGE_THRESHOLD || s.received == 0) return Health.BAD
        val loss = s.lossPercent
        return when {
            loss >= 3 -> Health.BAD
            loss >= 1 || t.inSpike -> Health.WARN
            else -> Health.GOOD
        }
    }
}

class TargetsTable(
    private val engine: MonitorEngine,
    private val state: ChartState,
    private val onTraceroute: (Target) -> Unit,
) : JTable() {
    val tableModel = TargetsTableModel(engine, state)

    init {
        model = tableModel
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        rowHeight = 30
        showVerticalLines = false
        showHorizontalLines = true
        fillsViewportHeight = true
        autoCreateRowSorter = false
        tableHeader.reorderingAllowed = false
        setDefaultRenderer(Any::class.java, Renderer())
        val widths = listOf(30, 90, 80, 170, 130, 70, 70, 70, 70, 70, 70, 60, 60)
        widths.forEachIndexed { i, w -> columnModel.getColumn(i).preferredWidth = w }
        columnModel.getColumn(0).maxWidth = 34
        columnModel.getColumn(0).minWidth = 30

        selectionModel.addListSelectionListener {
            if (!it.valueIsAdjusting) {
                state.selectedId = selectedRow.takeIf { r -> r >= 0 }?.let { r -> tableModel.rows.getOrNull(r)?.first?.id }
                state.changed()
            }
        }
        addMouseListener(object : MouseAdapter() {
            override fun mousePressed(e: MouseEvent) {
                val row = rowAtPoint(e.point)
                if (row < 0) { clearSelection(); return }
                val target = tableModel.rows[row].first
                if (e.isPopupTrigger) popup(e, row)
                else if (columnAtPoint(e.point) == 0) {
                    target.visible = !target.visible
                    state.changed()
                    repaint()
                } else if (e.clickCount == 2 && target.kind == ProbeKind.ICMP) onTraceroute(target)
            }
            override fun mouseReleased(e: MouseEvent) {
                val row = rowAtPoint(e.point)
                if (e.isPopupTrigger && row >= 0) popup(e, row)
            }
        })
        toolTipText = ""
    }

    override fun getToolTipText(e: MouseEvent): String? {
        val row = rowAtPoint(e.point); val col = columnAtPoint(e.point)
        if (row < 0) return null
        val (t, s) = tableModel.rows[row]
        return when (col) {
            0 -> "Click to ${if (t.visible) "hide" else "show"} in chart"
            10 -> "${s.lost} of ${s.sent} probes lost in the selected window"
            else -> t.resolveError ?: "${t.name} — ${t.displayAddress}" +
                (if (t.kind == ProbeKind.DNS) " (DNS query for ${t.dnsQuery})" else "") +
                (if (t.kind == ProbeKind.ICMP) "\nDouble-click to run a traceroute" else "")
        }
    }

    override fun updateUI() {
        super.updateUI()
        rowHeight = 30
    }

    private fun popup(e: MouseEvent, row: Int) {
        setRowSelectionInterval(row, row)
        val t = tableModel.rows[row].first
        JPopupMenu().apply {
            if (t.kind == ProbeKind.ICMP) add(JMenuItem("Traceroute to ${t.displayAddress}").apply { addActionListener { onTraceroute(t) } })
            add(JMenuItem("Copy address").apply {
                addActionListener { Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(t.displayAddress), null) }
            })
            add(JMenuItem(if (t.visible) "Hide in chart" else "Show in chart").apply {
                addActionListener { t.visible = !t.visible; state.changed(); repaint() }
            })
            addSeparator()
            add(JMenuItem("Remove").apply { addActionListener { engine.removeTarget(t) } })
        }.show(this, e.x, e.y)
    }

    private inner class Renderer : DefaultTableCellRenderer() {
        private var swatch: java.awt.Color? = null
        private var swatchFilled = true
        private var chip: java.awt.Color? = null

        override fun getTableCellRendererComponent(
            table: JTable, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, column: Int,
        ): Component {
            super.getTableCellRendererComponent(table, "", isSelected, false, row, column)
            @Suppress("UNCHECKED_CAST")
            val (t, s) = value as Pair<Target, Summary>
            swatch = null; chip = null
            icon = null
            font = table.font
            foreground = if (isSelected) table.selectionForeground else Theme.foreground
            horizontalAlignment = if (column >= 5) SwingConstants.RIGHT else SwingConstants.LEFT
            border = javax.swing.BorderFactory.createEmptyBorder(0, 8, 0, 10)
            val ms = { v: Double -> if (v.isNaN()) "—" else "%.1f".format(v) }
            text = when (column) {
                0 -> { swatch = Theme.series(t.colorIndex); swatchFilled = t.visible; "" }
                1 -> {
                    val h = tableModel.health(t, s)
                    icon = DotIcon({ Theme.health(h) })
                    iconTextGap = 7
                    when {
                        t.resolveError != null -> "Unresolved"
                        h == Health.UNKNOWN -> "Waiting"
                        t.consecutiveLost >= MonitorEngine.OUTAGE_THRESHOLD -> "Down"
                        h == Health.BAD -> "Lossy"
                        h == Health.WARN -> if (t.inSpike) "Slow" else "Unstable"
                        else -> "OK"
                    }
                }
                2 -> {
                    chip = roleColor(t.role)
                    foreground = java.awt.Color(0, 0, 0, 0) // text is painted on the pill instead
                    horizontalAlignment = SwingConstants.CENTER
                    t.role.label
                }
                3 -> { font = table.font.deriveFont(Font.BOLD); t.name }
                4 -> t.displayAddress
                5 -> if (s.sent == 0) "—" else if (t.samples.lastOrNull()?.lost == true) "lost" else ms(t.samples.last().rtt.toDouble())
                6 -> ms(s.avg)
                7 -> ms(s.min)
                8 -> ms(s.max)
                9 -> ms(s.jitter)
                10 -> {
                    if (!isSelected && s.sent > 0) foreground = when {
                        s.lossPercent >= 3 -> Theme.bad
                        s.lossPercent > 0 -> Theme.warn
                        else -> Theme.good
                    }
                    font = table.font.deriveFont(Font.BOLD)
                    if (s.sent == 0) "—" else Diagnoser.pct(s.lossPercent)
                }
                11 -> s.sent.toString()
                12 -> s.lost.toString()
                else -> ""
            }
            if (column == 5 && text == "lost" && !isSelected) foreground = Theme.bad
            return this
        }

        override fun paintComponent(g: Graphics) {
            super.paintComponent(g)
            val g2 = Theme.smooth(g)
            swatch?.let { c ->
                val s = 12.0
                val shape = RoundRectangle2D.Double((width - s) / 2, (height - s) / 2, s, s, 4.0, 4.0)
                g2.color = c
                if (swatchFilled) g2.fill(shape) else { g2.stroke = java.awt.BasicStroke(1.5f); g2.draw(shape) }
            }
            chip?.let { c ->
                val label = text
                // Repaint text on a tinted pill.
                val fm = g2.getFontMetrics(font)
                val w = fm.stringWidth(label) + 16.0
                val h = fm.height + 2.0
                val shape = RoundRectangle2D.Double((width - w) / 2, (height - h) / 2, w, h, h, h)
                g2.color = Theme.alpha(c, if (Theme.isDark) 0.22 else 0.14)
                g2.fill(shape)
            }
            g2.dispose()
            if (chip != null) {
                val g3 = Theme.smooth(g)
                g3.font = font
                g3.color = chip
                val fm = g3.fontMetrics
                g3.drawString(text, (width - fm.stringWidth(text)) / 2, (height - fm.height) / 2 + fm.ascent)
                g3.dispose()
            }
        }
    }

    private fun roleColor(r: TargetRole) = when (r) {
        TargetRole.GATEWAY -> Theme.series(1)
        TargetRole.ISP -> Theme.series(3)
        TargetRole.INTERNET -> Theme.series(0)
        TargetRole.DNS -> Theme.series(2)
        TargetRole.CUSTOM -> Theme.series(4)
    }

}
