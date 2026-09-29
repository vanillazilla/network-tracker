package com.networktracker.ui.traffic

import com.networktracker.capture.Conversation
import com.networktracker.capture.Packet
import com.networktracker.capture.TrafficStore
import com.networktracker.ui.Theme
import java.awt.BasicStroke
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Graphics
import java.awt.Window
import java.awt.geom.Line2D
import java.awt.geom.Path2D
import javax.swing.BorderFactory
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextPane
import javax.swing.JToggleButton
import javax.swing.ButtonGroup
import javax.swing.ListSelectionModel
import javax.swing.SwingConstants
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.TableRowSorter
import javax.swing.text.DefaultHighlighter
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants

fun formatBytes(b: Long): String = when {
    b < 1024 -> "$b B"
    b < 1024 * 1024 -> "%.1f KB".format(b / 1024.0)
    b < 1024L * 1024 * 1024 -> "%.1f MB".format(b / 1048576.0)
    else -> "%.2f GB".format(b / 1073741824.0)
}

fun formatRate(bytesPerSec: Double): String {
    val bits = bytesPerSec * 8
    return when {
        bits < 1000 -> "%.0f bps".format(bits)
        bits < 1_000_000 -> "%.1f kbps".format(bits / 1000)
        bits < 1_000_000_000 -> "%.1f Mbps".format(bits / 1_000_000)
        else -> "%.2f Gbps".format(bits / 1_000_000_000)
    }
}

fun formatDuration(micros: Long): String {
    val s = micros / 1_000_000.0
    return when {
        s < 1 -> "%.0f ms".format(s * 1000)
        s < 60 -> "%.1f s".format(s)
        s < 3600 -> "%dm %02ds".format((s / 60).toInt(), (s % 60).toInt())
        else -> "%dh %02dm".format((s / 3600).toInt(), ((s % 3600) / 60).toInt())
    }
}

/** Column definition for [DataTable]: [value] is used for sorting, [text] for display. */
class Col<T>(
    val name: String,
    val width: Int,
    val right: Boolean = false,
    val bold: Boolean = false,
    val tip: ((T) -> String?)? = null,
    val color: ((T) -> Color?)? = null,
    val text: ((T) -> String)? = null,
    val value: (T) -> Comparable<*>?,
)

/** Sortable table over a list of row objects, keeping the selection across refreshes. */
class DataTable<T>(val cols: List<Col<T>>, private val key: (T) -> Any) : JTable() {
    var rows: List<T> = emptyList(); private set
    private val m = object : AbstractTableModel() {
        override fun getRowCount() = rows.size
        override fun getColumnCount() = cols.size
        override fun getColumnName(c: Int) = cols[c].name
        override fun getValueAt(r: Int, c: Int): Any? = cols[c].value(rows[r])
        override fun getColumnClass(c: Int): Class<*> = Any::class.java
    }
    private val sorter = TableRowSorter(m).apply {
        for (i in cols.indices) setComparator(i, Comparator<Any?> { a, b ->
            @Suppress("UNCHECKED_CAST")
            when {
                a == null && b == null -> 0; a == null -> -1; b == null -> 1
                a is Number && b is Number -> a.toDouble().compareTo(b.toDouble())
                else -> (a as Comparable<Any>).compareTo(b as Any)
            }
        })
    }

    init {
        model = m
        rowSorter = sorter
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        fillsViewportHeight = true
        showVerticalLines = false
        tableHeader.reorderingAllowed = false
        autoResizeMode = AUTO_RESIZE_SUBSEQUENT_COLUMNS
        cols.forEachIndexed { i, c -> columnModel.getColumn(i).preferredWidth = c.width }
        setDefaultRenderer(Any::class.java, object : DefaultTableCellRenderer() {
            override fun getTableCellRendererComponent(t: JTable, v: Any?, sel: Boolean, f: Boolean, r: Int, c: Int): Component {
                val row = rows.getOrNull(convertRowIndexToModel(r))
                val col = cols[convertColumnIndexToModel(c)]
                @Suppress("UNCHECKED_CAST")
                val text = if (row == null) "" else col.text?.invoke(row) ?: (v?.toString() ?: "")
                super.getTableCellRendererComponent(t, text, sel, false, r, c)
                border = BorderFactory.createEmptyBorder(0, 8, 0, 8)
                horizontalAlignment = if (col.right) SwingConstants.RIGHT else SwingConstants.LEFT
                font = if (col.bold) t.font.deriveFont(Font.BOLD) else t.font
                foreground = if (sel) t.selectionForeground else (row?.let { col.color?.invoke(it) } ?: Theme.foreground)
                toolTipText = row?.let { col.tip?.invoke(it) } ?: text.takeIf { it.length > 30 }
                return this
            }
        })
    }

    override fun updateUI() { super.updateUI(); rowHeight = 26 }

    fun setRows(newRows: List<T>) {
        val selKey = selected()?.let(key)
        rows = newRows
        m.fireTableDataChanged()
        if (selKey != null) {
            val idx = rows.indexOfFirst { key(it) == selKey }
            if (idx >= 0) {
                val v = convertRowIndexToView(idx)
                if (v >= 0) selectionModel.setSelectionInterval(v, v)
            }
        }
    }

    fun selected(): T? = selectedRow.takeIf { it >= 0 }?.let { rows.getOrNull(convertRowIndexToModel(it)) }

    fun rowAt(y: Int): T? = rowAtPoint(java.awt.Point(0, y)).takeIf { it >= 0 }?.let {
        setRowSelectionInterval(it, it); rows.getOrNull(convertRowIndexToModel(it))
    }
}

/** Classic offset / hex / ASCII dump with highlighting of the selected field's bytes. */
class HexView : JTextArea() {
    private var data = ByteArray(0)
    private val painter get() = DefaultHighlighter.DefaultHighlightPainter(Theme.alpha(Theme.accent, 0.45))

    init {
        isEditable = false
        font = Font(Font.MONOSPACED, Font.PLAIN, Theme.font().size)
        border = BorderFactory.createEmptyBorder(6, 8, 6, 8)
    }

    fun show(bytes: ByteArray) {
        data = bytes
        val sb = StringBuilder(bytes.size * 4 + 64)
        var i = 0
        while (i < bytes.size) {
            sb.append("%04x  ".format(i))
            for (j in 0 until 16) {
                if (i + j < bytes.size) sb.append("%02x ".format(bytes[i + j])) else sb.append("   ")
                if (j == 7) sb.append(' ')
            }
            sb.append(' ')
            for (j in 0 until minOf(16, bytes.size - i)) {
                val c = bytes[i + j].toInt() and 0xFF
                sb.append(if (c in 32..126) c.toChar() else '·')
            }
            sb.append('\n')
            i += 16
        }
        text = sb.toString()
        caretPosition = 0
    }

    fun highlight(offset: Int, length: Int) {
        highlighter.removeAllHighlights()
        if (length <= 0 || offset < 0 || offset >= data.size) return
        val end = minOf(data.size, offset + length)
        val lineLen = 6 + 16 * 3 + 1 + 1 + 16 + 1
        var first = -1
        for (b in offset until end) {
            val line = b / 16; val col = b % 16
            val lineStart = line * lineLen
            val hexPos = lineStart + 6 + col * 3 + (if (col >= 8) 1 else 0)
            val asciiPos = lineStart + 6 + 16 * 3 + 2 + col
            runCatching {
                highlighter.addHighlight(hexPos, hexPos + 2, painter)
                highlighter.addHighlight(asciiPos, asciiPos + 1, painter)
            }
            if (first < 0) first = hexPos
        }
        if (first >= 0) runCatching { scrollRectToVisible(modelToView2D(first).bounds) }
    }
}

/** Live bandwidth graph: received (filled) and sent (line), last two minutes. */
class RateGraph : JComponent() {
    var inRates = DoubleArray(0)
    var outRates = DoubleArray(0)

    init { preferredSize = Dimension(260, 44) }

    override fun paintComponent(g: Graphics) {
        val g2 = Theme.smooth(g)
        val w = width.toDouble(); val h = height.toDouble() - 2
        g2.color = Theme.track
        g2.fillRoundRect(0, 0, width, height, 8, 8)
        val n = maxOf(inRates.size, outRates.size)
        if (n < 2) { g2.dispose(); return }
        val max = maxOf(1.0, inRates.maxOrNull() ?: 0.0, outRates.maxOrNull() ?: 0.0) * 1.15
        fun x(i: Int) = i * w / (n - 1)
        fun y(v: Double) = h - v / max * (h - 4) + 1
        val area = Path2D.Double(); area.moveTo(0.0, h)
        inRates.forEachIndexed { i, v -> area.lineTo(x(i), y(v)) }
        area.lineTo(w, h); area.closePath()
        g2.color = Theme.alpha(Theme.series(0), 0.35); g2.fill(area)
        g2.color = Theme.series(0); g2.stroke = BasicStroke(1.2f)
        for (i in 1 until inRates.size) g2.draw(Line2D.Double(x(i - 1), y(inRates[i - 1]), x(i), y(inRates[i])))
        g2.color = Theme.series(3); g2.stroke = BasicStroke(1.5f)
        for (i in 1 until outRates.size) g2.draw(Line2D.Double(x(i - 1), y(outRates[i - 1]), x(i), y(outRates[i])))
        g2.dispose()
    }
}

/** Shows the payload of one conversation as a readable, two-coloured transcript. */
class FollowStreamDialog(owner: Window?, private val store: TrafficStore, private val conv: Conversation) :
    JDialog(owner, "Follow stream — conversation #${conv.id}", ModalityType.MODELESS) {
    private val pane = JTextPane().apply { isEditable = false; font = Font(Font.MONOSPACED, Font.PLAIN, Theme.font().size) }
    private val asciiBtn = JToggleButton("Text", true)
    private val hexBtn = JToggleButton("Hex")

    init {
        val a = store.nameOf(conv.aAddr)?.let { "$it (${conv.aAddr})" } ?: conv.aAddr
        val b = store.nameOf(conv.bAddr)?.let { "$it (${conv.bAddr})" } ?: conv.bAddr
        val header = JLabel("<html><b>${conv.protocol}</b> &nbsp; <span style='color:${Theme.hex(Theme.series(0))}'>■ $a:${conv.aPort}</span>" +
            " &nbsp;⇄&nbsp; <span style='color:${Theme.hex(Theme.series(3))}'>■ $b:${conv.bPort}</span>" +
            (conv.app?.let { " &nbsp;·&nbsp; app: $it" } ?: "") + "</html>")
        val note = JLabel().apply { foreground = Theme.muted }
        ButtonGroup().apply { add(asciiBtn); add(hexBtn) }
        asciiBtn.addActionListener { render() }
        hexBtn.addActionListener { render() }
        val top = JPanel(BorderLayout(8, 6)).apply {
            border = BorderFactory.createEmptyBorder(10, 12, 6, 12)
            add(header, BorderLayout.CENTER)
            add(JPanel(FlowLayout(FlowLayout.RIGHT, 4, 0)).apply { add(asciiBtn); add(hexBtn) }, BorderLayout.EAST)
            add(note, BorderLayout.SOUTH)
        }
        if (conv.protocol.startsWith("TLS") || conv.protocol == "QUIC" || conv.protocol == "HTTPS")
            note.text = "This conversation is encrypted, so its content is unreadable — that is normal and expected."
        contentPane = JPanel(BorderLayout()).apply {
            add(top, BorderLayout.NORTH)
            add(JScrollPane(pane), BorderLayout.CENTER)
        }
        size = Dimension(900, 640)
        setLocationRelativeTo(owner)
        render()
    }

    private fun render() {
        val doc = pane.styledDocument
        doc.remove(0, doc.length)
        val styles = listOf(Theme.series(0), Theme.series(3)).map { c -> SimpleAttributeSet().also { StyleConstants.setForeground(it, c) } }
        var total = 0
        for (p in store.packets) {
            if (p.conv !== conv || p.retransmission) continue
            val d = com.networktracker.capture.Dissector.dissect(p.raw.data, store.linkType, false)
            if (d.payloadLength <= 0 || d.payloadOffset < 0) continue
            val bytes = p.raw.data.copyOfRange(d.payloadOffset, minOf(p.raw.data.size, d.payloadOffset + d.payloadLength))
            val fromA = p.src == conv.aAddr && (conv.aPort < 0 || p.srcPort == conv.aPort)
            val text = if (hexBtn.isSelected) hexLines(bytes) else String(bytes, Charsets.ISO_8859_1)
                .map { if (it == '\n' || it == '\r' || it == '\t' || it in ' '..'~') it else '·' }.joinToString("")
            doc.insertString(doc.length, text + if (hexBtn.isSelected) "\n" else "", styles[if (fromA) 0 else 1])
            total += bytes.size
            if (total > 2_000_000) { doc.insertString(doc.length, "\n… truncated at 2 MB …", null); break }
        }
        if (total == 0) doc.insertString(0, "No payload data captured for this conversation (only headers / handshakes).", null)
        pane.caretPosition = 0
    }

    private fun hexLines(b: ByteArray) = b.toList().chunked(16).joinToString("\n") { row -> row.joinToString(" ") { "%02x".format(it) } }
}

fun describePacketShort(p: Packet, s: TrafficStore): String = "#${p.no} ${p.protocol} ${s.nameOf(p.src) ?: p.src} → ${s.nameOf(p.dst) ?: p.dst}"
