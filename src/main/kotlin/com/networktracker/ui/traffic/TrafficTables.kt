package com.networktracker.ui.traffic

import com.networktracker.capture.CaptureEngine
import com.networktracker.capture.Conversation
import com.networktracker.capture.Device
import com.networktracker.capture.Dissector
import com.networktracker.capture.PacketFilter
import com.networktracker.capture.ProtoStat
import com.networktracker.capture.SocketEntry
import com.networktracker.capture.TcpState
import com.networktracker.capture.TrafficStore
import com.networktracker.ui.Card
import com.networktracker.ui.Theme
import java.awt.BorderLayout
import java.awt.Component
import java.awt.FlowLayout
import java.awt.Graphics
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.BorderFactory
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.table.DefaultTableCellRenderer

private val clock = SimpleDateFormat("HH:mm:ss")
private fun time(micros: Long) = if (micros <= 0) "—" else clock.format(Date(micros / 1000))

/** Common layout: summary line + table in a card, double-click and context menu hooks. */
abstract class TableView<T>(cols: List<Col<T>>, key: (T) -> Any, hint: String) : JPanel(BorderLayout(0, 8)) {
    val table = DataTable(cols, key)
    protected val summary = JLabel(" ")
    protected val options = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 0)).apply { isOpaque = false }

    init {
        isOpaque = false
        val top = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(summary, BorderLayout.WEST)
            add(options, BorderLayout.EAST)
        }
        add(top, BorderLayout.NORTH)
        add(Card(null, JScrollPane(table).apply { border = BorderFactory.createEmptyBorder() }), BorderLayout.CENTER)
        add(JLabel(hint).apply { foreground = Theme.muted; font = Theme.font(java.awt.Font.PLAIN, -1f) }, BorderLayout.SOUTH)
        table.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2) table.selected()?.let { open(it) }
            }
            override fun mousePressed(e: MouseEvent) = popup(e)
            override fun mouseReleased(e: MouseEvent) = popup(e)
        })
    }

    private fun popup(e: MouseEvent) {
        if (!e.isPopupTrigger) return
        val row = table.rowAt(e.y) ?: return
        val menu = JPopupMenu()
        menuItems(row).forEach { (label, action) ->
            if (label == "-") menu.addSeparator() else menu.add(JMenuItem(label).apply { addActionListener { action() } })
        }
        menu.show(table, e.x, e.y)
    }

    protected fun copy(s: String) = Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(s), null)

    abstract fun open(row: T)
    abstract fun menuItems(row: T): List<Pair<String, () -> Unit>>
    abstract fun refresh(filter: PacketFilter)
}

class ConversationsView(
    private val store: TrafficStore,
    private val onFilter: (String) -> Unit,
    private val onFollow: (Conversation) -> Unit,
) : TableView<Conversation>(listOf(
    Col("#", 44, right = true) { it.id },
    Col("Protocol", 80, bold = true, color = { protocolColor(it.protocol) }) { it.protocol },
    Col("App", 110) { it.app ?: "" },
    Col("Address A", 150, text = { c -> store.nameOf(c.aAddr)?.let { "$it" } ?: c.aAddr }, tip = { "${it.aAddr}:${it.aPort}" }) { it.aAddr },
    Col("Port A", 60, right = true, text = { if (it.aPort < 0) "" else "${it.aPort}" }) { it.aPort },
    Col("Address B", 200, text = { c -> store.nameOf(c.bAddr) ?: c.bAddr }, tip = { c -> "${c.bAddr}:${c.bPort}" + (store.nameOf(c.bAddr)?.let { "  ($it)" } ?: "") }) { store.nameOf(it.bAddr) ?: it.bAddr },
    Col("Port B", 60, right = true, text = { if (it.bPort < 0) "" else "${it.bPort}" }) { it.bPort },
    Col("Packets", 70, right = true) { it.packets },
    Col("Sent A→B", 80, right = true, text = { formatBytes(it.bytesAB) }) { it.bytesAB },
    Col("Recv B→A", 80, right = true, text = { formatBytes(it.bytesBA) }) { it.bytesBA },
    Col("Duration", 76, right = true, text = { formatDuration(it.last - it.first) }) { it.last - it.first },
    Col("Started", 70, text = { time(it.first) }) { it.first },
    Col("Issues", 150, color = { if (it.problems > 0) Theme.bad else Theme.muted }, text = { c ->
        listOfNotNull(
            c.retransmissions.takeIf { it > 0 }?.let { "$it retrans" },
            c.resets.takeIf { it > 0 }?.let { "$it reset" },
            (c.problems - c.retransmissions - c.resets).takeIf { it > 0 }?.let { "$it other" },
        ).joinToString(", ").ifEmpty { "—" }
    }) { it.problems },
), { it.id }, "A conversation is all packets between two endpoints (address + port). A = this computer when it is involved. Double-click to show its packets; right-click to follow the stream.") {

    override fun open(row: Conversation) = onFilter("conv:${row.id}")

    override fun menuItems(row: Conversation) = listOfNotNull(
        "Show packets of this conversation" to { onFilter("conv:${row.id}") },
        ("Follow stream…" to { onFollow(row) }).takeIf { row.transport == "TCP" || row.transport == "UDP" },
        "Show all traffic with ${store.nameOf(row.bAddr) ?: row.bAddr}" to { onFilter("ip:${row.bAddr}") },
        "-" to {},
        "Copy remote address" to { copy(row.bAddr) },
    )

    override fun refresh(filter: PacketFilter) {
        val rows = store.conversations.values.filter { c ->
            filter.matchesText(mapOf("proto" to c.protocol + " " + c.transport, "app" to (c.app ?: ""), "src" to c.aAddr, "dst" to c.bAddr,
                "host" to ((store.nameOf(c.bAddr) ?: "") + " " + (store.nameOf(c.aAddr) ?: "")), "sport" to "${c.aPort}", "dport" to "${c.bPort}",
                "problems" to "${c.problems}", "conv" to "${c.id}"))
        }
        table.setRows(rows)
        summary.text = "${rows.size} conversations" + if (rows.size != store.conversations.size) " (of ${store.conversations.size})" else ""
    }
}

class AppStat(val name: String) {
    var packets = 0L; var sent = 0L; var recv = 0L; var conversations = 0; var problems = 0
    val hosts = LinkedHashMap<String, Long>()
    var pid: Int? = null
}

class ApplicationsView(private val store: TrafficStore, private val onFilter: (String) -> Unit) : TableView<AppStat>(listOf(
    Col("Application", 170, bold = true) { it.name },
    Col("PID", 60, right = true, text = { it.pid?.toString() ?: "" }) { it.pid ?: -1 },
    Col("Total", 80, right = true, text = { formatBytes(it.sent + it.recv) }) { it.sent + it.recv },
    Col("Sent", 80, right = true, text = { formatBytes(it.sent) }, color = { Theme.series(3) }) { it.sent },
    Col("Received", 80, right = true, text = { formatBytes(it.recv) }, color = { Theme.series(0) }) { it.recv },
    Col("Packets", 70, right = true) { it.packets },
    Col("Conversations", 90, right = true) { it.conversations },
    Col("Talks to", 420, text = { a -> a.hosts.entries.sortedByDescending { it.value }.take(4).joinToString(", ") { store.nameOf(it.key) ?: it.key } +
        if (a.hosts.size > 4) "  +${a.hosts.size - 4} more" else "" }, tip = { a -> a.hosts.keys.joinToString("\n") { store.nameOf(it)?.let { n -> "$n ($it)" } ?: it } }) { it.hosts.size },
    Col("Issues", 60, right = true, color = { if (it.problems > 0) Theme.bad else Theme.muted }) { it.problems },
), { it.name }, "Traffic of this computer grouped by the program that owns each connection. Double-click to see an app's packets.") {

    override fun open(row: AppStat) = onFilter("app:\"${row.name}\"")
    override fun menuItems(row: AppStat) = listOf("Show packets of ${row.name}" to { onFilter("app:\"${row.name}\"") }, "Copy name" to { copy(row.name) })

    override fun refresh(filter: PacketFilter) {
        val stats = LinkedHashMap<String, AppStat>()
        for (c in store.conversations.values) {
            if (!c.aIsLocal) continue
            val name = c.app ?: if (c.transport == "TCP" || c.transport == "UDP") "Unknown (closed before it could be identified)" else "System (${c.transport})"
            val s = stats.getOrPut(name) { AppStat(name) }
            s.pid = c.pid ?: s.pid
            s.packets += c.packets; s.sent += c.bytesAB; s.recv += c.bytesBA; s.conversations++; s.problems += c.problems
            s.hosts.merge(c.bAddr, c.bytes, Long::plus)
        }
        val rows = stats.values.filter { filter.matchesText(mapOf("app" to it.name, "host" to it.hosts.keys.joinToString(" ") { h -> (store.nameOf(h) ?: "") + " " + h })) }
            .sortedByDescending { it.sent + it.recv }
        table.setRows(rows)
        summary.text = "${rows.size} applications with network traffic"
    }
}

class DevicesView(private val store: TrafficStore, private val onFilter: (String) -> Unit) : TableView<Device>(listOf(
    Col("Type", 80, bold = true, color = { d -> when { d.isThisPc -> Theme.series(0); d.isRouter -> Theme.series(1); else -> Theme.foreground } }) { it.kind },
    Col("Name", 170, text = { d -> d.name ?: d.ips.firstNotNullOfOrNull { store.nameOf(it) } ?: "" }) { it.name ?: "" },
    Col("IP addresses", 220, text = { it.ips.joinToString(", ") }) { it.ips.firstOrNull() ?: "" },
    Col("MAC address", 150, tip = { if (it.randomized) "Randomized / private MAC: phones and laptops use these for privacy" else "Hardware address" },
        text = { it.mac + if (it.randomized && it.kind == "Device") "  (private)" else "" }) { it.mac },
    Col("Announces itself as", 260, text = { it.info ?: "" }) { it.info ?: "" },
    Col("Packets", 70, right = true) { it.packets },
    Col("Bytes", 80, right = true, text = { formatBytes(it.bytes) }) { it.bytes },
    Col("First seen", 70, text = { time(it.firstSeen) }) { it.firstSeen },
    Col("Last seen", 70, text = { time(it.lastSeen) }) { it.lastSeen },
), { it.mac }, "Devices on your local network, found from the ARP table and from broadcasts they send (ARP, DHCP, mDNS, SSDP, NetBIOS). On Wi-Fi you only see other devices' broadcasts, not their private traffic.") {

    override fun open(row: Device) = onFilter("mac:${row.mac}")
    override fun menuItems(row: Device) = listOfNotNull(
        "Show packets from/to this device" to { onFilter("mac:${row.mac}") },
        row.ips.firstOrNull()?.let { ip -> "Show traffic with $ip" to { onFilter("ip:$ip") } },
        "Copy MAC address" to { copy(row.mac) },
        row.ips.firstOrNull()?.let { ip -> "Copy IP address" to { copy(ip) } },
    )

    override fun refresh(filter: PacketFilter) {
        val rows = store.devices.values.filter { it.kind != "Multicast" }.filter { d ->
            filter.matchesText(mapOf("host" to ((d.name ?: "") + " " + d.ips.joinToString(" ") + " " + (d.info ?: "")), "src" to d.ips.joinToString(" "),
                "mac" to d.mac))
        }.sortedWith(compareBy({ !it.isThisPc }, { !it.isRouter }, { it.ips.firstOrNull() ?: "~" }))
        table.setRows(rows)
        summary.text = "${rows.size} devices seen on your network"
    }
}

class ProtocolsView(private val store: TrafficStore, private val onFilter: (String) -> Unit) : TableView<ProtoStat>(listOf(
    Col("Protocol", 260, bold = true, text = { "      ".repeat(it.depth) + it.name }, color = { protocolColor(it.name) }) { it.path },
    Col("Packets", 90, right = true) { it.packets },
    Col("% of packets", 200, text = { "%.1f%%".format(pct(it.packets, store.totalPackets)) }) { it.packets },
    Col("Bytes", 90, right = true, text = { formatBytes(it.bytes) }) { it.bytes },
    Col("% of bytes", 200, text = { "%.1f%%".format(pct(it.bytes, store.totalBytes)) }) { it.bytes },
), { it.path }, "Protocol hierarchy: how much of the traffic is carried by each protocol at each layer. Double-click to filter by a protocol.") {

    init {
        // Draw percentage columns as bars.
        val bar = object : DefaultTableCellRenderer() {
            var fraction = 0.0
            override fun getTableCellRendererComponent(t: JTable, v: Any?, s: Boolean, f: Boolean, r: Int, c: Int): Component {
                val row = table.rows[table.convertRowIndexToModel(r)]
                fraction = if (table.convertColumnIndexToModel(c) == 2) pct(row.packets, store.totalPackets) / 100 else pct(row.bytes, store.totalBytes) / 100
                super.getTableCellRendererComponent(t, "%.1f%%".format(fraction * 100), s, false, r, c)
                border = BorderFactory.createEmptyBorder(0, 8, 0, 8)
                foreground = if (s) t.selectionForeground else Theme.foreground
                return this
            }
            override fun paintComponent(g: Graphics) {
                val g2 = Theme.smooth(g)
                val w = (width - 70).coerceAtLeast(10)
                g2.color = Theme.track; g2.fillRoundRect(62, height / 2 - 4, w, 8, 8, 8)
                g2.color = Theme.series(0); g2.fillRoundRect(62, height / 2 - 4, (w * fraction).toInt().coerceAtLeast(2), 8, 8, 8)
                g2.dispose()
                super.paintComponent(g)
            }
        }
        table.columnModel.getColumn(2).cellRenderer = bar
        table.columnModel.getColumn(4).cellRenderer = bar
    }

    override fun open(row: ProtoStat) = onFilter("proto:${row.name.lowercase()}")
    override fun menuItems(row: ProtoStat) = listOf("Show ${row.name} packets" to { onFilter("proto:${row.name.lowercase()}") },
        "Hide ${row.name} packets" to { onFilter("-proto:${row.name.lowercase()}") })

    override fun refresh(filter: PacketFilter) {
        table.setRows(store.protocols.values.sortedBy { it.path })
        summary.text = "${store.totalPackets} packets · ${formatBytes(store.totalBytes)} total"
    }

    companion object { fun pct(a: Long, b: Long) = if (b == 0L) 0.0 else a * 100.0 / b }
}

/** Live connection table from the OS: works without any capture driver. */
class ConnectionsView(private val engine: CaptureEngine, private val onFilter: (String) -> Unit) : TableView<SocketEntry>(listOf(
    Col("Application", 160, bold = true, text = { appName(engine, it.pid) }) { appName(engine, it.pid) },
    Col("PID", 60, right = true) { it.pid },
    Col("Proto", 56) { it.protocol },
    Col("Local address", 190, text = { "${it.localAddress}:${it.localPort}" }) { it.localPort },
    Col("Remote address", 190, text = { if (it.remoteAddress == null || it.remotePort == 0) "—" else "${it.remoteAddress}:${it.remotePort}" }) { it.remoteAddress ?: "" },
    Col("Remote host", 240, text = { s -> s.remoteAddress?.let { engine.store.nameOf(it) } ?: "" }) { s -> s.remoteAddress?.let { engine.store.nameOf(it) } ?: "" },
    Col("Service", 110, text = { s -> Dissector.service(if (s.remotePort > 0) s.remotePort else s.localPort) ?: "" }) { it.remotePort },
    Col("State", 100, color = { s -> when (s.state) { TcpState.ESTABLISHED -> Theme.good; TcpState.LISTEN -> Theme.muted; TcpState.SYN_SENT -> Theme.warn; else -> Theme.foreground } }) { it.state.label },
), { it.key }, "Every network connection open on this computer and the program that owns it. Updated every second; no capture driver needed.") {

    private val showListening = JCheckBox("Show listening / idle sockets", false)
    private val showLoopback = JCheckBox("Show loopback (127.0.0.1)", false)

    init {
        options.add(showListening); options.add(showLoopback)
        showListening.addActionListener { refresh(lastFilter) }
        showLoopback.addActionListener { refresh(lastFilter) }
    }

    private var lastFilter = PacketFilter.EMPTY

    override fun open(row: SocketEntry) { row.remoteAddress?.takeIf { row.remotePort > 0 }?.let { onFilter("ip:$it") } }
    override fun menuItems(row: SocketEntry) = listOfNotNull(
        row.remoteAddress?.takeIf { row.remotePort > 0 }?.let { ip -> "Show captured packets with $ip" to { onFilter("ip:$ip") } },
        "Show captured packets of ${appName(engine, row.pid)}" to { onFilter("app:\"${appName(engine, row.pid)}\"") },
        row.remoteAddress?.let { ip -> "Copy remote address" to { copy(ip) } },
    )

    override fun refresh(filter: PacketFilter) {
        lastFilter = filter
        val rows = engine.sockets.filter { s ->
            (showListening.isSelected || (s.protocol == "TCP" && s.state != TcpState.LISTEN && s.remotePort != 0)) &&
                (showLoopback.isSelected || (s.localAddress != "127.0.0.1" && s.localAddress != "::1" && s.remoteAddress != "127.0.0.1" && s.remoteAddress != "::1"))
        }.filter { s ->
            filter.matchesText(mapOf("app" to appName(engine, s.pid), "proto" to s.protocol, "src" to s.localAddress, "dst" to (s.remoteAddress ?: ""),
                "host" to (s.remoteAddress?.let { engine.store.nameOf(it) } ?: ""), "sport" to "${s.localPort}", "dport" to "${s.remotePort}",
                "state" to s.state.label))
        }.sortedWith(compareBy({ appName(engine, it.pid).lowercase() }, { it.remoteAddress ?: "" }))
        table.setRows(rows)
        val established = rows.count { it.state == TcpState.ESTABLISHED }
        summary.text = "${rows.size} sockets · $established established · ${rows.map { it.pid }.distinct().size} applications"
    }

    companion object {
        fun appName(engine: CaptureEngine, pid: Int) = engine.store.processNames[pid]?.removeSuffix(".exe") ?: if (pid == 0) "System" else "PID $pid"
    }
}

