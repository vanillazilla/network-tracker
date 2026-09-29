package com.networktracker.ui.traffic

import com.networktracker.capture.Direction
import com.networktracker.capture.Dissection
import com.networktracker.capture.Dissector
import com.networktracker.capture.Field
import com.networktracker.capture.Packet
import com.networktracker.capture.PacketFilter
import com.networktracker.capture.TrafficStore
import com.networktracker.ui.Card
import com.networktracker.ui.Theme
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Graphics
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.geom.RoundRectangle2D
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JEditorPane
import javax.swing.JMenu
import javax.swing.JMenuItem
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.JTree
import javax.swing.ListSelectionModel
import javax.swing.SwingConstants
import javax.swing.SwingUtilities
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel
import javax.swing.tree.TreePath

/** Protocol → colour used for the protocol chip, so the list is scannable at a glance. */
fun protocolColor(proto: String): Color {
    val p = proto.uppercase()
    return when {
        p.startsWith("TLS") || p == "QUIC" || p == "HTTPS" || p == "SSH" -> Theme.series(2)
        p == "DNS" || p == "MDNS" || p == "LLMNR" || p == "NETBIOS-NS" -> Theme.series(1)
        p.startsWith("HTTP") || p == "SSDP" || p == "WS-DISCOVERY" -> Theme.series(5)
        p == "ARP" || p == "DHCP" || p == "DHCPV6" || p == "IGMP" || p == "LLDP" || p == "EAPOL" || p == "STP" -> Theme.series(7)
        p.startsWith("ICMP") -> Theme.series(4)
        p == "TCP" -> Theme.series(0)
        p == "UDP" -> Theme.series(6)
        p == "NTP" || p == "STUN" -> Theme.series(8)
        else -> Theme.unknown
    }
}

class PacketsView(
    private val store: TrafficStore,
    private val onFilter: (String) -> Unit,
    private val onFollow: (Packet) -> Unit,
) : JPanel(BorderLayout()) {
    var filter: PacketFilter = PacketFilter.EMPTY
    var autoScroll = true
    var absoluteTime = false
    private val view = ArrayList<Packet>()
    private var viewEvicted = 0L
    private val clock = SimpleDateFormat("HH:mm:ss.SSS")

    private val cols = listOf("No.", "Time", "", "Source", "Destination", "Protocol", "Length", "App", "Info")
    private val model = object : AbstractTableModel() {
        override fun getRowCount() = view.size
        override fun getColumnCount() = cols.size
        override fun getColumnName(c: Int) = cols[c]
        override fun getValueAt(r: Int, c: Int): Any = view[r]
    }
    private val table = object : JTable(model) {
        override fun updateUI() { super.updateUI(); rowHeight = 24 }
    }
    private val tree = JTree(DefaultTreeModel(DefaultMutableTreeNode("")))
    private val hex = HexView()
    private val explain = JEditorPane("text/html", "").apply {
        isEditable = false; isOpaque = false
        putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, true)
        border = BorderFactory.createEmptyBorder(2, 2, 8, 2)
    }
    private val detailButtons = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply { isOpaque = false }
    private var current: Packet? = null

    init {
        isOpaque = false
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        table.showVerticalLines = false
        table.fillsViewportHeight = true
        table.tableHeader.reorderingAllowed = false
        table.autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
        val widths = listOf(64, 96, 26, 200, 200, 86, 60, 110, 520)
        val minimums = listOf(50, 80, 26, 140, 140, 70, 50, 70, 200)
        widths.forEachIndexed { i, w ->
            table.columnModel.getColumn(i).preferredWidth = w
            table.columnModel.getColumn(i).minWidth = minimums[i]
        }
        table.columnModel.getColumn(2).maxWidth = 30
        table.setDefaultRenderer(Any::class.java, Renderer())
        table.selectionModel.addListSelectionListener { if (!it.valueIsAdjusting) showSelected() }
        table.addMouseListener(object : MouseAdapter() {
            override fun mousePressed(e: MouseEvent) = maybePopup(e)
            override fun mouseReleased(e: MouseEvent) = maybePopup(e)
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2) selectedPacket()?.let { p -> p.conv?.let { onFollow(p) } }
            }
        })
        val listScroll = JScrollPane(table).apply { border = BorderFactory.createEmptyBorder() }
        listScroll.verticalScrollBar.addAdjustmentListener {
            // Scrolling away from the bottom pauses auto-scroll; returning to the bottom resumes it.
            if (it.valueIsAdjusting) {
                val sb = listScroll.verticalScrollBar
                autoScroll = sb.value + sb.visibleAmount >= sb.maximum - 30
            }
        }

        tree.isRootVisible = false
        tree.showsRootHandles = true
        tree.addTreeSelectionListener {
            val f = (it.path?.lastPathComponent as? DefaultMutableTreeNode)?.userObject as? Field
            if (f != null) hex.highlight(f.offset, f.length)
        }
        val treePanel = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(JPanel(BorderLayout()).apply { isOpaque = false; add(explain, BorderLayout.CENTER); add(detailButtons, BorderLayout.SOUTH) }, BorderLayout.NORTH)
            add(JScrollPane(tree).apply { border = BorderFactory.createEmptyBorder(6, 0, 0, 0) }, BorderLayout.CENTER)
        }
        val detailSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            Card("Packet details", treePanel), Card("Bytes", JScrollPane(hex).apply { border = BorderFactory.createEmptyBorder() })).apply {
            resizeWeight = 0.58; border = null; dividerSize = 10; isOpaque = false
        }
        val main = JSplitPane(JSplitPane.VERTICAL_SPLIT, Card(null, listScroll), detailSplit).apply {
            resizeWeight = 0.55; border = null; dividerSize = 10; isOpaque = false
        }
        add(main, BorderLayout.CENTER)
        showPacket(null)
    }

    /** Appends a batch (empty batch = full rebuild after clear/load/eviction). */
    fun append(batch: List<Packet>) {
        if (batch.isEmpty() || store.evicted != viewEvicted) { rebuild(); return }
        val start = view.size
        for (p in batch) if (filter.matches(p, store)) view += p
        if (view.size > start) {
            model.fireTableRowsInserted(start, view.size - 1)
            if (autoScroll && table.selectedRow < 0) scrollToEnd()
        }
    }

    fun rebuild() {
        val selected = selectedPacket()
        viewEvicted = store.evicted
        view.clear()
        for (p in store.packets) if (filter.matches(p, store)) view += p
        model.fireTableDataChanged()
        val idx = selected?.let { view.indexOf(it) } ?: -1
        if (idx >= 0) { table.setRowSelectionInterval(idx, idx); table.scrollRectToVisible(table.getCellRect(idx, 0, true)) }
        else { showPacket(null); if (autoScroll) scrollToEnd() }
    }

    val visibleCount get() = view.size
    fun visiblePackets(): List<Packet> = view.toList()

    private fun scrollToEnd() = SwingUtilities.invokeLater {
        if (view.isNotEmpty()) table.scrollRectToVisible(table.getCellRect(view.size - 1, 0, true))
    }

    fun refreshNames() = table.repaint()

    private fun selectedPacket(): Packet? = table.selectedRow.takeIf { it >= 0 }?.let { view.getOrNull(it) }

    private fun showSelected() = showPacket(selectedPacket())

    private fun timeText(p: Packet) = if (absoluteTime) clock.format(Date(p.time / 1000))
        else "%.6f".format((p.time - store.firstTime) / 1e6)

    private fun showPacket(p: Packet?) {
        current = p
        detailButtons.removeAll()
        if (p == null) {
            explain.text = html("<span style='color:${Theme.hex(Theme.muted)}'>Select a packet to see a plain-English explanation, every decoded field, and the raw bytes.</span>")
            tree.model = DefaultTreeModel(DefaultMutableTreeNode(""))
            hex.show(ByteArray(0))
            detailButtons.revalidate(); detailButtons.repaint()
            return
        }
        val d = Dissector.dissect(p.raw.data, store.linkType, true, p.no, p.length, clock.format(Date(p.time / 1000)) + "  (+" + timeText(p) + " s)")
        val root = DefaultMutableTreeNode("root")
        fun addNodes(parent: DefaultMutableTreeNode, fields: List<Field>) {
            for (f in fields) { val n = DefaultMutableTreeNode(f); parent.add(n); addNodes(n, f.children) }
        }
        addNodes(root, d.tree)
        if (p.info.startsWith("[")) root.add(DefaultMutableTreeNode(Field("Analysis", p.info.substringBefore("] ").trim('[', ']'), 0, 0)))
        tree.model = DefaultTreeModel(root)
        // Expand the highest decoded layer (the most interesting one); lower layers stay collapsed.
        val top = (root.childCount - 1 downTo 0).map { root.getChildAt(it) as DefaultMutableTreeNode }
            .firstOrNull { it.childCount > 0 }
        if (top != null) tree.expandPath(TreePath(arrayOf(root, top)))
        hex.show(p.raw.data)
        explain.text = html(explanation(p, d))
        p.conv?.let { c ->
            detailButtons.add(small("Only this conversation") { onFilter("conv:${c.id}") })
            if (p.transport == "TCP" || p.transport == "UDP") detailButtons.add(small("Follow stream") { onFollow(p) })
        }
        store.appOf(p)?.let { app -> detailButtons.add(small("Only $app") { onFilter("app:\"$app\"") }) }
        detailButtons.revalidate(); detailButtons.repaint()
    }

    private fun small(text: String, action: () -> Unit) = JButton(text).apply {
        putClientProperty("JButton.buttonType", "roundRect")
        font = Theme.font(Font.PLAIN, -1f)
        addActionListener { action() }
    }

    private fun html(body: String): String {
        val f = Theme.font()
        return "<html><body style='font-family:\"${f.family}\"; font-size:${f.size}pt; color:${Theme.hex(Theme.foreground)}'>$body</body></html>"
    }

    private fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    private fun who(addr: String, p: Packet): String {
        val local = addr in store.localAddrs
        val name = store.nameOf(addr)
        val app = if (local) store.appOf(p) else null
        return when {
            local -> "<b>This PC</b>" + (app?.let { " (<b>${esc(it)}</b>)" } ?: "")
            name != null -> "<b>${esc(name)}</b> <span style='color:${Theme.hex(Theme.muted)}'>($addr)</span>"
            addr == store.gateway -> "<b>your router</b> ($addr)"
            else -> "<b>$addr</b>"
        }
    }

    /** One or two sentences describing what the packet is doing, for people who don't read hex. */
    private fun explanation(p: Packet, d: Dissection): String {
        val from = who(p.src, p); val to = who(p.dst, p)
        val svc = Dissector.service(p.dstPort)?.let { " ($it)" } ?: ""
        val f = d.tcpFlags
        val action = when {
            d.protocol == "DNS" || d.protocol == "mDNS" || d.protocol == "LLMNR" -> if (d.info.startsWith("Standard query response"))
                "$from answered a name lookup for $to: <i>${esc(d.info.substringAfter(' ').substringAfter(' ').substringAfter(' '))}</i>"
            else "$from asked $to to look up <i>${esc(d.info.substringAfter("0x").substringAfter(' '))}</i>"
            d.sni != null -> "$from started an <b>encrypted</b> (TLS) connection to <b>${esc(d.sni!!)}</b> — the site name is visible, the content is not."
            d.protocol.startsWith("TLS") && d.info.contains("Application Data") -> "$from sent <b>encrypted</b> data to $to. The content can't be read (this is normal for HTTPS)."
            d.protocol == "QUIC" -> "$from exchanged <b>encrypted QUIC</b> (HTTP/3) data with $to."
            d.protocol == "ARP" -> "Local network address lookup: <i>${esc(d.info)}</i>. Devices use ARP to find each other's hardware (MAC) address."
            d.protocol == "DHCP" -> "Automatic IP address assignment: <i>${esc(d.info)}</i>."
            d.protocol == "SSDP" -> "$from is discovering or announcing smart/UPnP devices on the local network."
            d.protocol == "NTP" -> "$from is synchronising its clock with $to."
            d.protocol.startsWith("ICMP") -> "$from → $to: <i>${esc(d.info)}</i>."
            p.transport == "TCP" && f and Dissector.SYN != 0 && f and Dissector.ACK == 0 -> "$from is <b>opening a connection</b> to $to on port ${p.dstPort}$svc."
            p.transport == "TCP" && f and Dissector.SYN != 0 -> "$from <b>accepted a connection</b> from $to."
            p.transport == "TCP" && f and Dissector.RST != 0 -> "$from <b>abruptly reset</b> the connection with $to."
            p.transport == "TCP" && f and Dissector.FIN != 0 -> "$from is <b>closing</b> its connection with $to."
            p.transport == "TCP" && d.payloadLength == 0 -> "$from acknowledged data from $to (no payload)."
            p.transport != null -> "$from sent ${d.payloadLength} bytes of ${esc(d.protocol)} data to $to${if (p.dstPort >= 0) " on port ${p.dstPort}$svc" else ""}."
            else -> "$from → $to: ${esc(d.info)}"
        }
        val dir = when (p.direction) { Direction.OUT -> "Outgoing"; Direction.IN -> "Incoming"; Direction.BROADCAST -> "Broadcast to the local network"; else -> "Between other devices" }
        val conv = p.conv?.let { c ->
            "<br><span style='color:${Theme.hex(Theme.muted)}'>$dir · ${p.length} bytes · conversation #${c.id}: ${c.packets} packets, ${formatBytes(c.bytes)}" +
                (if (c.retransmissions > 0) ", <span style='color:${Theme.hex(Theme.warn)}'>${c.retransmissions} retransmissions</span>" else "") +
                (c.app?.let { " · app ${esc(it)}" } ?: "") + "</span>"
        } ?: "<br><span style='color:${Theme.hex(Theme.muted)}'>$dir · ${p.length} bytes</span>"
        val problem = p.problem?.let { "<br><span style='color:${Theme.hex(Theme.bad)}'><b>⚠ ${esc(it)}</b></span>" } ?: ""
        return action + conv + problem
    }

    private fun maybePopup(e: MouseEvent) {
        if (!e.isPopupTrigger) return
        val row = table.rowAtPoint(e.point)
        if (row < 0) return
        table.setRowSelectionInterval(row, row)
        val p = view[row]
        val menu = JPopupMenu()
        val f = JMenu("Filter to")
        p.conv?.let { c -> f.add(item("This conversation (#${c.id})") { onFilter("conv:${c.id}") }) }
        f.add(item("Traffic to/from ${label(p.src)}") { onFilter("ip:${p.src}") })
        f.add(item("Traffic to/from ${label(p.dst)}") { onFilter("ip:${p.dst}") })
        f.add(item("Protocol ${p.protocol}") { onFilter("proto:${p.protocol.lowercase()}") })
        store.appOf(p)?.let { app -> f.add(item("App $app") { onFilter("app:\"$app\"") }) }
        if (p.dstPort >= 0) f.add(item("Port ${p.dstPort}") { onFilter("port:${p.dstPort}") })
        menu.add(f)
        val x = JMenu("Exclude")
        x.add(item("Protocol ${p.protocol}") { onFilter("-proto:${p.protocol.lowercase()}") })
        x.add(item("Host ${label(p.dst)}") { onFilter("-ip:${p.dst}") })
        menu.add(x)
        if (p.conv != null && (p.transport == "TCP" || p.transport == "UDP")) menu.add(item("Follow stream…") { onFollow(p) })
        menu.addSeparator()
        val c = JMenu("Copy")
        c.add(item("Summary") { copy("${p.no}\t${timeText(p)}\t${p.src}\t${p.dst}\t${p.protocol}\t${p.length}\t${p.info}") })
        c.add(item("Source address") { copy(p.src) })
        c.add(item("Destination address") { copy(p.dst) })
        c.add(item("Bytes as hex") { copy(p.raw.data.joinToString("") { "%02x".format(it) }) })
        menu.add(c)
        menu.show(table, e.x, e.y)
    }

    private fun label(addr: String) = store.nameOf(addr)?.let { "$it ($addr)" } ?: addr
    private fun item(text: String, action: () -> Unit) = JMenuItem(text).apply { addActionListener { action() } }
    private fun copy(s: String) = Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(s), null)

    private inner class Renderer : DefaultTableCellRenderer() {
        private var chip: Color? = null

        override fun getTableCellRendererComponent(t: JTable, v: Any?, sel: Boolean, f: Boolean, r: Int, c: Int): Component {
            super.getTableCellRendererComponent(t, "", sel, false, r, c)
            val p = v as Packet
            chip = null
            border = BorderFactory.createEmptyBorder(0, 6, 0, 6)
            horizontalAlignment = if (c == 0 || c == 6 || c == 1) SwingConstants.RIGHT else SwingConstants.LEFT
            font = t.font
            val problem = p.problem != null
            foreground = when {
                sel -> t.selectionForeground
                problem && c == 8 -> Theme.bad
                else -> Theme.foreground
            }
            if (!sel) background = if (problem) Theme.alpha(Theme.bad, if (Theme.isDark) 0.16 else 0.09).let { Theme.blend(t.background, it, it.alpha / 255.0) } else t.background
            text = when (c) {
                0 -> p.no.toString()
                1 -> timeText(p)
                2 -> { horizontalAlignment = SwingConstants.CENTER; when (p.direction) { Direction.OUT -> "↑"; Direction.IN -> "↓"; Direction.BROADCAST -> "⇶"; else -> "·" } }
                3 -> store.nameOf(p.src) ?: p.src
                4 -> store.nameOf(p.dst) ?: p.dst
                5 -> { chip = protocolColor(p.protocol); p.protocol }
                6 -> p.length.toString()
                7 -> store.appOf(p) ?: ""
                else -> p.info
            }
            if (c == 2 && !sel) foreground = when (p.direction) { Direction.OUT -> Theme.series(3); Direction.IN -> Theme.series(0); else -> Theme.muted }
            if (c == 5) { font = t.font.deriveFont(Font.BOLD, t.font.size2D - 1); if (!sel) foreground = chip }
            toolTipText = when (c) {
                3 -> "${p.src}${if (p.srcPort >= 0) ":${p.srcPort}" else ""}" + (p.srcMac?.let { "  ($it)" } ?: "")
                4 -> "${p.dst}${if (p.dstPort >= 0) ":${p.dstPort}" else ""}" + (p.dstMac?.let { "  ($it)" } ?: "")
                8 -> p.problem?.let { "⚠ $it" } ?: p.info.takeIf { it.length > 80 }
                else -> null
            }
            return this
        }

        override fun paintComponent(g: Graphics) {
            chip?.let { c ->
                val g2 = Theme.smooth(g)
                val w = g2.getFontMetrics(font).stringWidth(text) + 12.0
                g2.color = Theme.alpha(c, if (Theme.isDark) 0.18 else 0.12)
                g2.fill(RoundRectangle2D.Double(2.0, 3.0, w, height - 6.0, 8.0, 8.0))
                g2.dispose()
            }
            super.paintComponent(g)
        }
    }
}
