package com.networktracker.ui.traffic

import com.networktracker.capture.CaptureDevice
import com.networktracker.capture.CaptureEngine
import com.networktracker.capture.Conversation
import com.networktracker.capture.Packet
import com.networktracker.capture.PacketFilter
import com.networktracker.capture.Pcap
import com.networktracker.monitor.MonitorEngine
import com.networktracker.ui.Card
import com.networktracker.ui.Theme
import java.awt.BorderLayout
import java.awt.Desktop
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.io.File
import java.net.URI
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.ButtonGroup
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JEditorPane
import javax.swing.JFileChooser
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JTabbedPane
import javax.swing.JTextField
import javax.swing.JToggleButton
import javax.swing.SwingUtilities
import javax.swing.Timer
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.filechooser.FileNameExtensionFilter

class TrafficPanel(private val monitor: MonitorEngine) : JPanel(BorderLayout(0, 10)) {
    val engine = CaptureEngine(monitor.scope)
    private val store = engine.store

    private val deviceBox = JComboBox<CaptureDevice>()
    private val startButton = JButton("Start capture")
    private val promiscuous = JCheckBox("Promiscuous mode", false)
    private var bpf = ""
    private val filterField = JTextField()
    private val filterError = JLabel()
    private val autoScroll = JCheckBox("Auto-scroll", true)
    private val clockTime = JCheckBox("Clock time", false)
    private val rateGraph = RateGraph()
    private val rateLabel = JLabel()
    private val statusLabel = JLabel(" ")
    private val banner = JPanel(BorderLayout(12, 0))
    private val tabs = JTabbedPane()
    private var filter = PacketFilter.EMPTY

    private val packetsView = PacketsView(store, ::applyFilter, { p -> p.conv?.let(::follow) })
    private val conversationsView = ConversationsView(store, ::showPacketsWith, ::follow)
    private val appsView = ApplicationsView(store, ::showPacketsWith)
    private val devicesView = DevicesView(store, ::showPacketsWith)
    private val protocolsView = ProtocolsView(store, ::showPacketsWith)
    private val connectionsView = ConnectionsView(engine, ::showPacketsWith)
    private val tableViews get() = listOf(conversationsView, appsView, devicesView, protocolsView, connectionsView)

    private val presets = listOf(
        "All" to "",
        "Web" to "proto:http|tls|quic|https",
        "DNS" to "proto:dns|mdns|llmnr",
        "Local network" to "proto:arp|dhcp|mdns|ssdp|llmnr|netbios|igmp|lldp or dir:broadcast",
        "Problems" to "problems",
    )
    private val presetButtons = presets.map { (label, _) -> JToggleButton(label) }
    private val presetGroup = ButtonGroup()

    init {
        isOpaque = false
        border = BorderFactory.createEmptyBorder(12, 12, 12, 12)
        add(buildTop(), BorderLayout.NORTH)
        buildTabs()
        add(tabs, BorderLayout.CENTER)
        add(statusLabel.apply { foreground = Theme.muted }, BorderLayout.SOUTH)

        engine.onBatch { batch ->
            packetsView.append(batch)
            updateStatus()
        }
        engine.onState { updateState() }
        engine.onRefresh {
            engine.setLocalInfo(localAddrs(), monitor.adapter?.mac?.lowercase(), monitor.gateway)
            refreshVisible()
            updateRate()
        }
        Timer(2000) { packetsView.refreshNames() }.start()
        loadDevices()
        updateState()
    }

    // ---------------------------------------------------------------- layout

    private fun buildTop(): JPanel {
        deviceBox.preferredSize = Dimension(360, deviceBox.preferredSize.height)
        deviceBox.toolTipText = "Network adapter to capture on"
        startButton.putClientProperty("JButton.buttonType", "default")
        startButton.addActionListener { if (engine.capturing) engine.stop() else startCapture() }
        val options = JButton("Options…").apply { addActionListener { showOptions() } }
        val open = JButton("Open file…").apply { toolTipText = "Open a .pcap or .pcapng capture (e.g. from Wireshark)"; addActionListener { openFile() } }
        val save = JButton("Save ▾").apply { addActionListener { e -> savePopup(e.source as JButton) } }
        val clear = JButton("Clear").apply { addActionListener { engine.clear() } }

        val left = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0)).apply {
            isOpaque = false
            add(deviceBox); add(startButton); add(options); add(Box.createHorizontalStrut(8)); add(open); add(save); add(clear)
        }
        rateLabel.font = Theme.font(Font.PLAIN, -1f)
        val right = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 0)).apply { isOpaque = false; add(rateLabel); add(rateGraph) }
        val row1 = JPanel(BorderLayout()).apply { isOpaque = false; add(left, BorderLayout.WEST); add(right, BorderLayout.EAST) }

        filterField.putClientProperty("JTextField.placeholderText",
            "Filter — type anything (e.g. youtube), or proto:dns  app:chrome  host:google  port:443  dir:out  len>1000  problems  -proto:tls")
        filterField.putClientProperty("JTextField.showClearButton", true)
        filterField.font = Font(Font.MONOSPACED, Font.PLAIN, Theme.font().size)
        val debounce = Timer(300) { applyFilter(filterField.text, fromField = true) }.apply { isRepeats = false }
        filterField.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = debounce.restart()
            override fun removeUpdate(e: DocumentEvent) = debounce.restart()
            override fun changedUpdate(e: DocumentEvent) = debounce.restart()
        })
        filterField.addActionListener { applyFilter(filterField.text, fromField = true) }
        filterError.foreground = Theme.bad
        val help = JButton("?").apply { toolTipText = "Filter syntax"; addActionListener { showHelp() } }

        presetButtons.forEachIndexed { i, b ->
            presetGroup.add(b)
            b.putClientProperty("JButton.buttonType", "roundRect")
            b.addActionListener { applyFilter(presets[i].second) }
        }
        presetButtons[0].isSelected = true
        val chips = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0)).apply {
            isOpaque = false
            presetButtons.forEach { add(it) }
            add(Box.createHorizontalStrut(10)); add(autoScroll); add(clockTime)
        }
        autoScroll.addActionListener { packetsView.autoScroll = autoScroll.isSelected }
        clockTime.addActionListener { packetsView.absoluteTime = clockTime.isSelected; packetsView.refreshNames() }

        val filterRow = JPanel(GridBagLayout()).apply {
            isOpaque = false
            val c = GridBagConstraints().apply { fill = GridBagConstraints.HORIZONTAL; insets = Insets(0, 0, 0, 6) }
            add(filterField, c.apply { gridx = 0; weightx = 1.0 })
            add(help, c.apply { gridx = 1; weightx = 0.0 })
            add(chips, c.apply { gridx = 2 })
        }

        banner.isOpaque = false
        val col = JPanel(BorderLayout(0, 6)).apply {
            isOpaque = false
            add(row1, BorderLayout.NORTH)
            add(banner, BorderLayout.CENTER)
            add(JPanel(BorderLayout(0, 2)).apply { isOpaque = false; add(filterRow, BorderLayout.CENTER); add(filterError, BorderLayout.SOUTH) }, BorderLayout.SOUTH)
        }
        return col
    }

    private fun buildTabs() {
        tabs.putClientProperty("JTabbedPane.tabType", "card")
        tabs.addTab("Packets", packetsView)
        tabs.addTab("Conversations", conversationsView)
        tabs.addTab("Applications", appsView)
        tabs.addTab("Devices", devicesView)
        tabs.addTab("Protocols", protocolsView)
        tabs.addTab("Connections", connectionsView)
        tabs.setToolTipTextAt(5, "Open connections per program — works without Npcap")
        tabs.addChangeListener { refreshVisible() }
    }

    private fun buildBanner() {
        banner.removeAll()
        if (Pcap.available) { banner.isVisible = false; return }
        banner.isVisible = true
        val text = JEditorPane("text/html",
            "<html><body style='font-family:\"${Theme.font().family}\"; font-size:${Theme.font().size}pt; color:${Theme.hex(Theme.foreground)}'>" +
                "<b style='color:${Theme.hex(Theme.warn)}'>Packet capture needs Npcap.</b> Windows has no built-in way for apps to capture packets, " +
                "so install <b>Npcap</b> (free, from the Wireshark developers) with its default options, then click <i>Check again</i>. " +
                "Without it you can still use <b>Connections</b>, the bandwidth graph, and open saved .pcap files.</body></html>").apply {
            isEditable = false; isOpaque = false
            putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, true)
        }
        val buttons = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 0)).apply {
            isOpaque = false
            add(JButton("Get Npcap").apply {
                putClientProperty("JButton.buttonType", "default")
                addActionListener { runCatching { Desktop.getDesktop().browse(URI("https://npcap.com/#download")) } }
            })
            add(JButton("Check again").apply {
                addActionListener {
                    if (Pcap.reload()) { loadDevices(); updateState() }
                    else JOptionPane.showMessageDialog(this@TrafficPanel, "Npcap still wasn't found (${Pcap.loadError}).", "Npcap", JOptionPane.INFORMATION_MESSAGE)
                }
            })
            add(JButton("✕").apply {
                toolTipText = "Hide this message"
                putClientProperty("JButton.buttonType", "borderless")
                addActionListener { banner.isVisible = false; this@TrafficPanel.revalidate() }
            })
        }
        banner.add(Card(null, JPanel(BorderLayout(12, 0)).apply {
            isOpaque = false; add(text, BorderLayout.CENTER); add(buttons, BorderLayout.EAST)
        }), BorderLayout.CENTER)
    }

    // ---------------------------------------------------------------- behaviour

    private var cachedAddrs: Set<String> = emptySet()
    private var addrsAt = 0L

    /** This computer's addresses (refreshed every 30 s; enumerating adapters is slow on Windows). */
    private fun localAddrs(): Set<String> {
        if (System.currentTimeMillis() - addrsAt < 30_000 && cachedAddrs.isNotEmpty()) return cachedAddrs
        cachedAddrs = buildSet {
            monitor.adapter?.localAddress?.let { add(it) }
            java.net.NetworkInterface.networkInterfaces().forEach { nif ->
                if (nif.isUp) nif.inetAddresses().forEach { add(com.networktracker.capture.SystemNet.compactV6(it.hostAddress.substringBefore('%'))) }
            }
        }
        addrsAt = System.currentTimeMillis()
        return cachedAddrs
    }

    private fun loadDevices() {
        buildBanner()
        deviceBox.removeAllItems()
        deviceBox.isVisible = Pcap.available
        if (!Pcap.available) {
            deviceBox.isEnabled = false
            if (tabs.selectedIndex == 0) tabs.selectedIndex = 5
            return
        }
        val devs = engine.devices().filter { it.addresses.isNotEmpty() || it.loopback }
        devs.forEach { deviceBox.addItem(it) }
        val mine = monitor.adapter?.localAddress
        devs.firstOrNull { mine != null && mine in it.addresses }?.let { deviceBox.selectedItem = it }
        deviceBox.isEnabled = true
        revalidate(); repaint()
    }

    private fun startCapture() {
        val dev = deviceBox.selectedItem as? CaptureDevice ?: return
        engine.start(dev, bpf, promiscuous.isSelected, localAddrs(), monitor.adapter?.mac?.lowercase(), monitor.gateway)
        engine.error?.let { JOptionPane.showMessageDialog(this, it, "Capture failed", JOptionPane.ERROR_MESSAGE) }
        tabs.selectedIndex = 0
    }

    private fun updateState() {
        val cap = engine.capturing
        startButton.isEnabled = Pcap.available
        startButton.text = if (cap) "Stop capture" else "Start capture"
        startButton.putClientProperty("JButton.buttonType", if (cap) null else "default")
        deviceBox.isEnabled = Pcap.available && !cap
        updateStatus()
    }

    private fun updateStatus() {
        val src = if (engine.capturing) "● Capturing on ${engine.sourceLabel}" else if (engine.sourceLabel.isNotEmpty()) "Stopped · ${engine.sourceLabel}" else "Not capturing"
        val shown = if (filter.isEmpty) "" else " · ${"%,d".format(packetsView.visibleCount)} shown"
        val drops = engine.droppedByDriver + engine.droppedByApp
        statusLabel.text = "$src · ${"%,d".format(store.totalPackets)} packets$shown · ${formatBytes(store.totalBytes)}" +
            (if (drops > 0) " · $drops dropped" else "") +
            (if (store.evicted > 0) " · oldest ${"%,d".format(store.evicted)} packets discarded to save memory" else "") +
            (Pcap.version?.let { " · $it" } ?: "")
    }

    private fun updateRate() {
        val useCapture = engine.capturing
        val inR: DoubleArray; val outR: DoubleArray
        if (useCapture) {
            inR = store.rateIn.map { it.toDouble() }.toDoubleArray().copyOfRange(60, 119)
            outR = store.rateOut.map { it.toDouble() }.toDoubleArray().copyOfRange(60, 119)
        } else {
            inR = engine.sysIn.toDoubleArray(); outR = engine.sysOut.toDoubleArray()
        }
        rateGraph.inRates = inR; rateGraph.outRates = outR
        rateGraph.repaint()
        val c = engine.counters
        val errs = c?.let { it.inErrors + it.outErrors + it.inDiscards + it.outDiscards } ?: 0
        rateLabel.text = "<html><span style='color:${Theme.hex(Theme.series(0))}'>↓ ${formatRate(inR.lastOrNull() ?: 0.0)}</span> &nbsp;" +
            "<span style='color:${Theme.hex(Theme.series(3))}'>↑ ${formatRate(outR.lastOrNull() ?: 0.0)}</span>" +
            (if (errs > 0) "<br><span style='color:${Theme.hex(Theme.warn)}'>adapter errors/discards: $errs</span>" else "") + "</html>"
        rateLabel.toolTipText = c?.let {
            "Adapter since boot — errors in ${it.inErrors} / out ${it.outErrors}, discards in ${it.inDiscards} / out ${it.outDiscards}, link ${formatRate(it.speedBps / 8.0)}"
        }
    }

    private fun refreshVisible() {
        when (tabs.selectedIndex) {
            1 -> conversationsView.refresh(filter)
            2 -> appsView.refresh(filter)
            3 -> devicesView.refresh(filter)
            4 -> protocolsView.refresh(filter)
            5 -> connectionsView.refresh(filter)
        }
    }

    private fun applyFilter(text: String) = applyFilter(text, false)

    private fun applyFilter(text: String, fromField: Boolean) {
        val parsed = try {
            PacketFilter.parse(text).also {
                filterError.text = ""
                filterField.putClientProperty("JComponent.outline", null)
            }
        } catch (e: IllegalArgumentException) {
            filterError.text = e.message
            filterField.putClientProperty("JComponent.outline", "error")
            return
        }
        if (!fromField && filterField.text != text) filterField.text = text
        if (parsed.text == filter.text) return
        filter = parsed
        packetsView.filter = parsed
        val preset = presets.indexOfFirst { it.second == text.trim() }
        if (preset >= 0) presetButtons[preset].isSelected = true else presetGroup.clearSelection()
        packetsView.rebuild()
        refreshVisible()
        updateStatus()
    }

    /** Called from the summary tabs: filter packets and jump to the Packets tab. */
    private fun showPacketsWith(expr: String) {
        applyFilter(expr)
        tabs.selectedIndex = 0
    }

    private fun follow(c: Conversation) {
        FollowStreamDialog(SwingUtilities.getWindowAncestor(this), store, c).isVisible = true
    }

    private fun showOptions() {
        val bpfField = JTextField(bpf, 30).apply {
            putClientProperty("JTextField.placeholderText", "e.g. not port 443   or   host 192.168.1.50")
        }
        val panel = JPanel(GridBagLayout())
        val c = GridBagConstraints().apply { anchor = GridBagConstraints.WEST; insets = Insets(4, 0, 4, 8); gridx = 0 }
        panel.add(JLabel("<html><b>Capture filter</b> (BPF syntax, applied by the driver — packets that don't match are never captured):</html>"), c.apply { gridy = 0 })
        panel.add(bpfField, c.apply { gridy = 1; fill = GridBagConstraints.HORIZONTAL })
        panel.add(promiscuous, c.apply { gridy = 2; fill = GridBagConstraints.NONE })
        panel.add(JLabel("<html><span style='color:${Theme.hex(Theme.muted)}'>Promiscuous mode also captures other devices' traffic that reaches your adapter<br>" +
            "(mostly useful on wired networks; Wi-Fi adapters usually ignore it).</span></html>"), c.apply { gridy = 3 })
        if (JOptionPane.showConfirmDialog(this, panel, "Capture options", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) == JOptionPane.OK_OPTION) {
            bpf = bpfField.text.trim()
            if (engine.capturing) startCapture()
        }
    }

    private fun showHelp() {
        val html = """
            <html><body style='font-family:"${Theme.font().family}"; width:560px'>
            <h3 style='margin-top:0'>Display filter</h3>
            Type words to search everything (addresses, host names, apps, protocols, info). Combine terms with spaces (all must match),
            use <b>or</b> for alternatives, and put <b>-</b> in front of a term to exclude it. Use <b>|</b> for several values.
            <table cellpadding='3'>
            <tr><td><code>youtube</code></td><td>anything mentioning youtube</td></tr>
            <tr><td><code>proto:dns|mdns</code></td><td>protocol at any layer (tcp, udp, tls, quic, http, arp, dhcp, icmp…)</td></tr>
            <tr><td><code>host:google</code></td><td>host name or address contains "google"</td></tr>
            <tr><td><code>ip:192.168.1.50</code> <code>src:</code> <code>dst:</code></td><td>address (either side, source, destination)</td></tr>
            <tr><td><code>port:443</code> <code>sport:</code> <code>dport:</code></td><td>port number</td></tr>
            <tr><td><code>app:chrome</code></td><td>program on this PC that owns the connection</td></tr>
            <tr><td><code>dir:in|out|broadcast</code></td><td>direction relative to this PC</td></tr>
            <tr><td><code>len&gt;1000</code> <code>len&lt;100</code></td><td>frame size in bytes</td></tr>
            <tr><td><code>flags:syn</code> <code>flags:rst</code></td><td>TCP flags</td></tr>
            <tr><td><code>problems</code></td><td>retransmissions, resets, lost segments, ICMP/DNS/TLS errors</td></tr>
            <tr><td><code>conv:12</code></td><td>one conversation</td></tr>
            <tr><td><code>mac:aa:bb:cc</code></td><td>MAC address prefix</td></tr>
            </table>
            <p><b>Examples</b>: <code>app:chrome -proto:quic</code> &nbsp; <code>proto:dns or proto:dhcp</code> &nbsp; <code>dir:out len&gt;1000</code></p>
            <p>Tip: right-click any packet or table row to filter by it, or double-click rows in the other tabs.</p>
            </body></html>
        """.trimIndent()
        JOptionPane.showMessageDialog(this, JLabel(html), "Filter syntax", JOptionPane.PLAIN_MESSAGE)
    }

    private fun openFile() {
        val fc = JFileChooser().apply { fileFilter = FileNameExtensionFilter("Capture files (*.pcap, *.pcapng, *.cap)", "pcap", "pcapng", "cap") }
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return
        statusLabel.text = "Loading ${fc.selectedFile.name}…"
        engine.openFile(fc.selectedFile, localAddrs()) { err ->
            if (err != null) JOptionPane.showMessageDialog(this, err, "Could not open file", JOptionPane.ERROR_MESSAGE)
            else { tabs.selectedIndex = 0; refreshVisible() }
            updateStatus()
        }
    }

    private fun savePopup(anchor: JButton) {
        JPopupMenu().apply {
            add(JMenuItem("Save all packets (.pcap)…").apply { addActionListener { save(store.packets.toList()) } })
            add(JMenuItem("Save displayed packets (.pcap)…").apply { addActionListener { save(packetsView.visiblePackets()) } })
        }.show(anchor, 0, anchor.height)
    }

    private fun save(packets: List<Packet>) {
        if (packets.isEmpty()) { JOptionPane.showMessageDialog(this, "There are no packets to save."); return }
        val fc = JFileChooser().apply {
            selectedFile = File(System.getProperty("user.home"), "capture-${java.text.SimpleDateFormat("yyyyMMdd-HHmmss").format(java.util.Date())}.pcap")
            fileFilter = FileNameExtensionFilter("pcap capture", "pcap")
        }
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return
        val f = fc.selectedFile.let { if (it.extension.equals("pcap", true)) it else File(it.path + ".pcap") }
        runCatching { engine.saveFile(f, packets) }
            .onSuccess { statusLabel.text = "Saved ${packets.size} packets to ${f.name} (opens in Wireshark)" }
            .onFailure { JOptionPane.showMessageDialog(this, "Could not save: ${it.message}", "Error", JOptionPane.ERROR_MESSAGE) }
    }

    fun shutdown() = engine.stop()
}
