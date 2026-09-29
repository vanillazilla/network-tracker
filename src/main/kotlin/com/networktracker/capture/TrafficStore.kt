package com.networktracker.capture

import java.net.InetAddress

enum class Direction(val label: String) { OUT("Out"), IN("In"), BROADCAST("Broadcast"), OTHER("Other") }

class Packet(
    val no: Long,
    val raw: RawPacket,
    val src: String,
    val dst: String,
    val srcPort: Int,
    val dstPort: Int,
    val protocol: String,
    var info: String,
    val path: String,
    val transport: String?,
    val direction: Direction,
    val tcpFlags: Int,
    val srcMac: String?,
    val dstMac: String?,
) {
    var problem: String? = null
    var conv: Conversation? = null
    var retransmission = false
    val time get() = raw.timeMicros
    val length get() = raw.originalLength
}

class Conversation(val id: Int, val transport: String, val aAddr: String, val aPort: Int, val bAddr: String, val bPort: Int) {
    var packetsAB = 0L; var packetsBA = 0L
    var bytesAB = 0L; var bytesBA = 0L
    var first = 0L; var last = 0L
    var protocol = transport
    var pid: Int? = null
    var app: String? = null
    var problems = 0
    var retransmissions = 0
    var resets = 0
    val packets get() = packetsAB + packetsBA
    val bytes get() = bytesAB + bytesBA
    /** Local side of the conversation (this PC), if any. */
    var aIsLocal = false

    // TCP analysis state per direction (index 0 = A→B, 1 = B→A)
    internal val nextSeq = LongArray(2) { -1 }
    internal val lastAck = LongArray(2) { -1 }
    internal val lastWin = IntArray(2) { -1 }
    internal val dupAcks = IntArray(2)

    val service: String get() = Dissector.service(bPort)?.takeIf { bPort < aPort || Dissector.service(aPort) == null }
        ?: Dissector.service(aPort) ?: ""
}

class Device(val mac: String) {
    val ips = linkedSetOf<String>()
    var name: String? = null
    var info: String? = null
    var firstSeen = 0L
    var lastSeen = 0L
    var packets = 0L
    var bytes = 0L
    var isRouter = false
    var isThisPc = false
    val randomized get() = (mac.substring(0, 2).toInt(16) and 2) != 0
    val kind: String get() = when {
        isThisPc -> "This PC"
        isRouter -> "Router"
        mac.startsWith("01:") || mac.startsWith("33:33") || mac == "ff:ff:ff:ff:ff:ff" -> "Multicast"
        else -> "Device"
    }
}

class ProtoStat(val path: String) {
    var packets = 0L
    var bytes = 0L
    val depth get() = path.count { it == '/' }
    val name get() = path.substringAfterLast('/')
}

/**
 * Holds captured packets and everything derived from them. Owned by the Swing thread; the capture
 * thread only hands over already-decoded packets.
 */
class TrafficStore {
    val packets = ArrayList<Packet>()
    var evicted = 0L; private set
    private var storedBytes = 0L
    var linkType = Pcap.DLT_EN10MB
    var nextNo = 1L
    var firstTime = 0L
    var totalPackets = 0L; private set
    var totalBytes = 0L; private set

    val conversations = LinkedHashMap<String, Conversation>()
    val devices = LinkedHashMap<String, Device>()
    val protocols = LinkedHashMap<String, ProtoStat>()
    val names = HashMap<String, String>()
    private var convIds = 0

    /** Addresses of this computer, for deciding in/out direction. */
    var localAddrs: Set<String> = emptySet()
    var localMac: String? = null
    var gateway: String? = null

    // Socket → process attribution
    private var socketMap: Map<String, Int> = emptyMap()
    var processNames: Map<Int, String> = emptyMap()

    // Per-second throughput (bytes), most recent last
    val rateIn = LongArray(120); val rateOut = LongArray(120)
    private var rateSecond = 0L

    fun clear() {
        packets.clear(); conversations.clear(); devices.clear(); protocols.clear()
        evicted = 0; storedBytes = 0; nextNo = 1; firstTime = 0; totalPackets = 0; totalBytes = 0; convIds = 0
        rateIn.fill(0); rateOut.fill(0)
    }

    fun updateSockets(sockets: List<SocketEntry>, procNames: Map<Int, String>) {
        val m = HashMap<String, Int>()
        for (s in sockets) if (s.pid > 0 || s.pid == 4) {
            m["${s.protocol}|${s.localPort}"] = s.pid
            if (s.remoteAddress != null) m["${s.protocol}|${s.localPort}|${s.remoteAddress}|${s.remotePort}"] = s.pid
        }
        socketMap = m
        processNames = procNames
        // Late attribution for conversations we couldn't match yet.
        for (c in conversations.values) if (c.app == null && c.aIsLocal) attribute(c)
    }

    private fun attribute(c: Conversation) {
        if (c.transport != "TCP" && c.transport != "UDP") return
        val pid = socketMap["${c.transport}|${c.aPort}|${c.bAddr}|${c.bPort}"] ?: socketMap["${c.transport}|${c.aPort}"] ?: return
        c.pid = pid
        c.app = processNames[pid]?.removeSuffix(".exe")?.removeSuffix(".EXE") ?: "PID $pid"
    }

    fun seedNames(pairs: List<Pair<String, String>>) {
        for ((ip, name) in pairs) if (ip !in names) names[ip] = name
    }

    fun nameOf(addr: String): String? = names[addr]

    fun add(raw: RawPacket, d: Dissection) {
        if (firstTime == 0L) firstTime = raw.timeMicros
        val src = d.src ?: d.srcMac ?: "?"
        val dst = d.dst ?: d.dstMac ?: "?"
        val dir = when {
            src in localAddrs || (d.src == null && d.srcMac == localMac) -> Direction.OUT
            dst in localAddrs || (d.dst == null && d.dstMac == localMac) -> Direction.IN
            d.broadcast -> Direction.BROADCAST
            else -> Direction.OTHER
        }
        val path = d.layers.joinToString("/").intern()
        val p = Packet(nextNo++, raw, src, dst, d.srcPort, d.dstPort, d.protocol, d.info, path, d.transport, dir,
            d.tcpFlags, d.srcMac, d.dstMac)
        p.problem = d.problem
        for ((ip, name) in d.names) if (name.isNotBlank()) names[ip] = name

        conversation(p, d)
        device(p, d, raw.originalLength)
        protocolStats(path, raw.originalLength)
        rate(raw.timeMicros, raw.originalLength, dir)

        packets += p
        storedBytes += raw.data.size + 200
        totalPackets++; totalBytes += raw.originalLength
        if (packets.size > MAX_PACKETS || storedBytes > MAX_BYTES) evict()
    }

    private fun evict() {
        val n = packets.size / 10
        for (i in 0 until n) storedBytes -= packets[i].raw.data.size + 200
        packets.subList(0, n).clear()
        evicted += n
    }

    private fun conversation(p: Packet, d: Dissection) {
        val t = p.transport ?: return
        if (d.src == null || d.dst == null) return
        val usePorts = t == "TCP" || t == "UDP"
        // Put this computer on the A side so "A→B" means "sent".
        val srcFirst = when {
            p.src in localAddrs -> true
            p.dst in localAddrs -> false
            else -> "${p.src}:${p.srcPort}" < "${p.dst}:${p.dstPort}"
        }
        val (aA, aP, bA, bP) = if (srcFirst) Quad(p.src, p.srcPort, p.dst, p.dstPort) else Quad(p.dst, p.dstPort, p.src, p.srcPort)
        val key = if (usePorts) "$t|$aA|$aP|$bA|$bP" else "$t|$aA|$bA"
        val c = conversations.getOrPut(key) {
            Conversation(++convIds, t, aA, if (usePorts) aP else -1, bA, if (usePorts) bP else -1).also {
                it.first = p.time
                it.aIsLocal = aA in localAddrs
                if (it.aIsLocal) attribute(it)
            }
        }
        p.conv = c
        c.last = p.time
        val len = p.length.toLong()
        if (srcFirst) { c.packetsAB++; c.bytesAB += len } else { c.packetsBA++; c.bytesBA += len }
        if (p.protocol !in GENERIC) c.protocol = p.protocol
        else if (c.protocol == t && usePorts) c.service.takeIf { it.isNotEmpty() }?.let { c.protocol = it }
        if (t == "TCP") tcpAnalysis(c, p, d, if (srcFirst) 0 else 1)
        if (p.problem != null) c.problems++
    }

    private data class Quad(val a: String, val b: Int, val c: String, val d: Int)

    /** Detects retransmissions, lost segments, duplicate ACKs, resets and zero windows. */
    private fun tcpAnalysis(c: Conversation, p: Packet, d: Dissection, dir: Int) {
        val flags = d.tcpFlags
        val syn = flags and Dissector.SYN != 0
        val fin = flags and Dissector.FIN != 0
        val rst = flags and Dissector.RST != 0
        val segLen = d.payloadLength + (if (syn) 1 else 0) + (if (fin) 1 else 0)
        val seq = d.tcpSeq
        val expected = c.nextSeq[dir]
        fun diff(a: Long, b: Long): Long = ((a - b + (1L shl 31)) and 0xFFFFFFFFL) - (1L shl 31)
        val tags = mutableListOf<String>()
        if (rst) { c.resets++ }
        if (expected >= 0 && segLen > 0) {
            val end = (seq + segLen) and 0xFFFFFFFFL
            when {
                d.payloadLength <= 1 && diff(seq, expected) == -1L && !syn && !fin -> tags += "Keep-alive"
                diff(end, expected) <= 0 -> {
                    tags += "Retransmission"; p.retransmission = true; c.retransmissions++
                    p.problem = p.problem ?: "TCP retransmission (a packet had to be resent: likely loss)"
                }
                diff(seq, expected) > 0 -> {
                    tags += "Previous segment not captured"
                    p.problem = p.problem ?: "Missing TCP segment (lost, or not captured)"
                }
            }
        }
        if (segLen > 0) {
            val end = (seq + segLen) and 0xFFFFFFFFL
            if (expected < 0 || diff(end, expected) > 0) c.nextSeq[dir] = end
        } else if (expected < 0) c.nextSeq[dir] = seq
        if (flags and Dissector.ACK != 0 && segLen == 0 && !rst) {
            if (d.tcpAck == c.lastAck[dir] && d.tcpWindow == c.lastWin[dir]) {
                c.dupAcks[dir]++
                tags += "Dup ACK #${c.dupAcks[dir]}"
                if (c.dupAcks[dir] >= 2) p.problem = p.problem ?: "Duplicate ACKs (receiver is missing data)"
            } else c.dupAcks[dir] = 0
        }
        if (flags and Dissector.ACK != 0) { c.lastAck[dir] = d.tcpAck; c.lastWin[dir] = d.tcpWindow }
        if (tags.isNotEmpty()) p.info = "[${tags.joinToString("] [")}] " + p.info
    }

    private fun device(p: Packet, d: Dissection, len: Int) {
        val now = p.time
        fun dev(mac: String): Device = devices.getOrPut(mac) { Device(mac).also { it.firstSeen = now } }
        val sm = p.srcMac ?: return
        val s = dev(sm)
        s.lastSeen = now; s.packets++; s.bytes += len
        if (sm == localMac) s.isThisPc = true
        val srcIp = d.src
        if (srcIp != null && isLanAddress(srcIp)) {
            s.ips += srcIp
            if (srcIp == gateway) s.isRouter = true
        }
        d.selfName?.takeIf { it.isNotBlank() }?.let { n -> (d.arpMac?.let { dev(it) } ?: s).name = n }
        d.deviceInfo?.takeIf { it.isNotBlank() }?.let { s.info = it }
        if (d.arpIp != null && d.arpMac != null && d.arpIp != "0.0.0.0") {
            val a = dev(d.arpMac!!)
            a.ips += d.arpIp!!
            if (d.arpIp == gateway) a.isRouter = true
        }
        p.dstMac?.let { dm ->
            if (dm != "ff:ff:ff:ff:ff:ff" && !dm.startsWith("01:") && !dm.startsWith("33:33")) {
                val t = dev(dm); t.lastSeen = now
                d.dst?.takeIf { isLanAddress(it) }?.let { t.ips += it; if (it == gateway) t.isRouter = true }
            }
        }
    }

    fun mergeArp(entries: List<ArpEntry>) {
        val now = System.currentTimeMillis() * 1000
        for (e in entries) {
            if (e.mac.startsWith("01:") || e.mac.startsWith("33:33") || e.mac == "ff:ff:ff:ff:ff:ff") continue
            val dvc = devices.getOrPut(e.mac) { Device(e.mac).also { it.firstSeen = now; it.lastSeen = now } }
            dvc.ips += e.ip
            if (e.ip == gateway) dvc.isRouter = true
        }
    }

    fun isLanAddress(ip: String): Boolean = ip.startsWith("fe80") || runCatching {
        val a = InetAddress.getByName(ip)
        a.isSiteLocalAddress || a.isLinkLocalAddress
    }.getOrDefault(false)

    private fun protocolStats(path: String, len: Int) {
        var i = path.indexOf('/')
        while (true) {
            val prefix = if (i < 0) path else path.substring(0, i)
            val s = protocols.getOrPut(prefix) { ProtoStat(prefix) }
            s.packets++; s.bytes += len
            if (i < 0) break
            i = path.indexOf('/', i + 1)
        }
    }

    private fun rate(timeMicros: Long, len: Int, dir: Direction) {
        val sec = timeMicros / 1_000_000
        if (rateSecond == 0L) rateSecond = sec
        if (sec > rateSecond) {
            val shift = (sec - rateSecond).coerceAtMost(120).toInt()
            System.arraycopy(rateIn, shift, rateIn, 0, 120 - shift); rateIn.fill(0, 120 - shift, 120)
            System.arraycopy(rateOut, shift, rateOut, 0, 120 - shift); rateOut.fill(0, 120 - shift, 120)
            rateSecond = sec
        }
        if (sec < rateSecond - 119) return
        val idx = 119 - (rateSecond - sec).toInt()
        if (dir == Direction.OUT) rateOut[idx] += len.toLong() else rateIn[idx] += len.toLong()
    }

    fun appOf(p: Packet): String? = p.conv?.app

    companion object {
        const val MAX_PACKETS = 500_000
        const val MAX_BYTES = 250L * 1024 * 1024
        private val GENERIC = setOf("TCP", "UDP", "IPv4", "IPv6", "Ethernet", "ICMP", "ICMPv6", "Frame")
    }
}
