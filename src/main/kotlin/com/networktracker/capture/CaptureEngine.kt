package com.networktracker.capture

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicLong
import javax.swing.Timer

/**
 * Runs packet capture on a background thread, decodes each frame's summary there, and hands batches
 * to the Swing thread. Also keeps the OS socket table, process names, ARP table, DNS cache and
 * interface counters fresh (these work without a capture driver).
 */
class CaptureEngine(private val scope: CoroutineScope) {
    val store = TrafficStore()
    private val queue = ConcurrentLinkedQueue<Pair<RawPacket, Dissection>>()
    private val queued = AtomicLong()
    @Volatile private var handle: Pcap.Handle? = null
    private var thread: Thread? = null

    var device: CaptureDevice? = null; private set
    var error: String? = null; private set
    var capturing = false; private set
    var droppedByDriver = 0L; private set
    var droppedByApp = 0L; private set
    var sourceLabel = ""; private set
    /** False while showing a capture file, so live system data isn't mixed into it. */
    var live = true; private set

    var sockets: List<SocketEntry> = emptyList(); private set
    var counters: IfCounters? = null; private set
    /** System-wide bytes/s from interface counters, most recent last (works without capture). */
    val sysIn = ArrayDeque<Double>(); val sysOut = ArrayDeque<Double>()
    private var lastCounters: IfCounters? = null
    private var lastCountersAt = 0L

    private val batchListeners = mutableListOf<(List<Packet>) -> Unit>()
    private val stateListeners = mutableListOf<() -> Unit>()
    private val refreshListeners = mutableListOf<() -> Unit>()
    fun onBatch(l: (List<Packet>) -> Unit) { batchListeners += l }
    fun onState(l: () -> Unit) { stateListeners += l }
    /** Once a second: sockets, counters and aggregate views refreshed. */
    fun onRefresh(l: () -> Unit) { refreshListeners += l }
    private fun stateChanged() = stateListeners.forEach { it() }

    private val drainTimer = Timer(250) { drain() }

    init {
        drainTimer.start()
        scope.launch { refreshLoop() }
    }

    private suspend fun refreshLoop() {
        var n = 0
        while (scope.isActive) {
            val snapshot = withContext(Dispatchers.IO) {
                val s = SystemNet.sockets()
                val procs = if (n % 3 == 0 || store.processNames.isEmpty()) SystemNet.processNames() else null
                val c = SystemNet.interfaceCounters()
                val arp = if (n % 10 == 0) SystemNet.arpTable() else null
                val dns = if (n % 30 == 0) SystemNet.dnsCache() else null
                Snapshot(s, procs, c, arp, dns)
            }
            sockets = snapshot.sockets
            store.updateSockets(snapshot.sockets, snapshot.procs ?: store.processNames)
            if (live) snapshot.arp?.let { store.mergeArp(it) }
            snapshot.dns?.let { store.seedNames(it) }
            snapshot.counters?.let { updateCounters(it) }
            resolveUnknownNames()
            refreshListeners.forEach { it() }
            n++
            delay(1000)
        }
    }

    /** Look up host names (reverse DNS) for addresses we have no name for yet, a few at a time. */
    var resolveNames = true
    private val resolving = HashSet<String>()
    private val unresolvable = HashSet<String>()

    private fun resolveUnknownNames() {
        if (!resolveNames) return
        val candidates = (sockets.mapNotNull { it.remoteAddress } + store.conversations.values.map { it.bAddr })
            .asSequence().distinct()
            .filter { it !in store.names && it !in resolving && it !in unresolvable && worthResolving(it) }
            .take((16 - resolving.size).coerceAtLeast(0)).toList()
        for (ip in candidates) {
            resolving += ip
            scope.launch {
                val name = withContext(Dispatchers.IO) {
                    runCatching { java.net.InetAddress.getByName(ip).canonicalHostName }.getOrNull()
                }
                resolving -= ip
                // On failure Java returns the address itself (possibly in another notation).
                val isAddress = name == null || name.contains(':') || name.all { it.isDigit() || it == '.' }
                if (!isAddress) store.names.putIfAbsent(ip, name!!) else unresolvable += ip
            }
        }
    }

    private fun worthResolving(ip: String): Boolean {
        if (ip == "0.0.0.0" || ip == "::" || ip.startsWith("127.") || ip == "::1" || ip.startsWith("fe80") || ip.startsWith("ff")) return false
        val first = ip.substringBefore('.').toIntOrNull()
        return first == null || first !in 224..255
    }

    private class Snapshot(val sockets: List<SocketEntry>, val procs: Map<Int, String>?, val counters: IfCounters?,
                           val arp: List<ArpEntry>?, val dns: List<Pair<String, String>>?)

    private fun updateCounters(c: IfCounters) {
        val now = System.nanoTime()
        lastCounters?.let { prev ->
            val secs = (now - lastCountersAt) / 1e9
            fun delta(a: Long, b: Long) = if (a >= b) a - b else a + (1L shl 32) - b // 32-bit counter wrap
            if (secs > 0.2) {
                sysIn.addLast(delta(c.inOctets, prev.inOctets) / secs)
                sysOut.addLast(delta(c.outOctets, prev.outOctets) / secs)
                while (sysIn.size > 120) sysIn.removeFirst()
                while (sysOut.size > 120) sysOut.removeFirst()
            }
        }
        counters = c; lastCounters = c; lastCountersAt = now
    }

    fun devices(): List<CaptureDevice> = Pcap.devices()

    /** Tell the store who "this PC" and the router are, so directions and device roles are right. */
    fun setLocalInfo(addrs: Set<String>, mac: String?, gateway: String?) {
        if (!live) return
        store.localAddrs = addrs
        store.localMac = mac
        store.gateway = gateway
        if (mac != null) store.devices.getOrPut(mac) {
            Device(mac).also { it.firstSeen = System.currentTimeMillis() * 1000; it.lastSeen = it.firstSeen }
        }.also { d -> d.isThisPc = true; d.ips += addrs.filter { store.isLanAddress(it) } }
        store.devices.values.forEach { d -> if (gateway != null && gateway in d.ips) d.isRouter = true }
    }

    fun start(dev: CaptureDevice, bpf: String, promiscuous: Boolean, localAddrs: Set<String>, localMac: String?, gateway: String?) {
        stop()
        error = null
        val h = try {
            Pcap.open(dev.name, promiscuous = promiscuous).also { if (bpf.isNotBlank()) it.setFilter(bpf) }
        } catch (e: Exception) {
            error = e.message ?: "Could not start capture"
            stateChanged()
            return
        }
        if (!live || (store.packets.isNotEmpty() && store.linkType != h.linkType)) store.clear()
        live = true
        store.linkType = h.linkType
        store.localAddrs = localAddrs + dev.addresses
        store.localMac = localMac
        store.gateway = gateway
        device = dev
        handle = h
        capturing = true
        sourceLabel = dev.description.ifBlank { dev.name }
        droppedByApp = 0
        val t = Thread({ captureLoop(h) }, "packet-capture").apply { isDaemon = true; priority = Thread.MAX_PRIORITY - 1 }
        thread = t
        t.start()
        stateChanged()
    }

    private fun captureLoop(h: Pcap.Handle) {
        val linkType = h.linkType
        try {
            while (handle === h) {
                val raw = h.next() ?: continue
                if (queued.get() > 200_000) { droppedByApp++; continue } // UI can't keep up; shed load
                val d = Dissector.dissect(raw.data, linkType, false, 0, raw.originalLength)
                queue += raw to d
                queued.incrementAndGet()
            }
        } catch (e: Exception) {
            if (handle === h) javax.swing.SwingUtilities.invokeLater {
                error = "Capture stopped: ${e.message}"
                stop()
            }
        }
    }

    fun stop() {
        val h = handle ?: return
        handle = null
        h.stats()?.let { droppedByDriver = it.second + it.third }
        h.breakLoop()
        thread?.join(1500)
        h.close()
        thread = null
        capturing = false
        drain()
        stateChanged()
    }

    private fun drain() {
        if (queue.isEmpty()) return
        val batch = ArrayList<Packet>(minOf(queue.size, 30_000))
        val deadline = System.nanoTime() + 60_000_000 // keep the UI responsive: ≤60 ms per drain
        while (System.nanoTime() < deadline) {
            val (raw, d) = queue.poll() ?: break
            queued.decrementAndGet()
            store.add(raw, d)
            batch += store.packets.last()
        }
        handle?.stats()?.let { droppedByDriver = it.second + it.third }
        if (batch.isNotEmpty()) batchListeners.forEach { it(batch) }
    }

    /** Loads a .pcap/.pcapng file into the store (replacing current data). */
    fun openFile(file: File, localAddrs: Set<String>, onDone: (String?) -> Unit) {
        stop()
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val c = PcapFile.read(file)
                    c to c.packets.map { Dissector.dissect(it.data, c.linkType, false, 0, it.originalLength) }
                }
            }
            result.onSuccess { (c, ds) ->
                live = false
                store.clear()
                store.linkType = c.linkType
                store.localAddrs = localAddrs
                c.packets.forEachIndexed { i, raw -> store.add(raw, ds[i]) }
                sourceLabel = file.name
                batchListeners.forEach { it(emptyList()) }
                stateChanged()
                onDone(null)
            }.onFailure { onDone(it.message ?: "Could not read file") }
        }
    }

    fun saveFile(file: File, packets: List<Packet>) {
        Pcap.writePcapFile(file, store.linkType, packets.map { it.raw })
    }

    fun clear() {
        queue.clear(); queued.set(0)
        store.clear()
        if (!live) sourceLabel = ""
        live = true
        batchListeners.forEach { it(emptyList()) }
        stateChanged()
    }
}
