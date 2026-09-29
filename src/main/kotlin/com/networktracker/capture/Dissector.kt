package com.networktracker.capture

import java.net.InetAddress

/** A node in the packet-details tree; [offset]/[length] locate its bytes in the frame for hex highlighting. */
class Field(val name: String, val value: String, val offset: Int, val length: Int) {
    val children = ArrayList<Field>(0)
    override fun toString() = if (value.isEmpty()) name else "$name: $value"
}

/**
 * Result of decoding one frame. With [detail] = false only the summary fields are filled (fast path used
 * for every captured packet); with [detail] = true the full field tree is built for the details pane.
 */
class Dissection(val data: ByteArray, val detail: Boolean) {
    val tree = ArrayList<Field>()
    val layers = ArrayList<String>(6)
    var protocol = "Frame"
    var info = ""
    var srcMac: String? = null
    var dstMac: String? = null
    var src: String? = null
    var dst: String? = null
    var srcPort = -1
    var dstPort = -1
    var transport: String? = null
    var ttl = -1
    var tcpFlags = 0
    var tcpSeq = 0L
    var tcpAck = 0L
    var tcpWindow = 0
    var payloadOffset = -1
    var payloadLength = 0
    var problem: String? = null
    var broadcast = false
    /** IP → host name pairs learned from this packet (DNS answers, TLS SNI, HTTP Host). */
    val names = ArrayList<Pair<String, String>>(0)
    /** A name the *sender* announced for itself (DHCP host name, mDNS, NetBIOS, LLDP). */
    var selfName: String? = null
    /** Device description announced by the sender (SSDP SERVER header, LLDP system description, DHCP vendor class). */
    var deviceInfo: String? = null
    var arpIp: String? = null
    var arpMac: String? = null
    var sni: String? = null
    var malformed = false

    inline fun node(parent: Field?, name: String, off: Int, len: Int, value: () -> String = { "" }): Field? {
        if (!detail) return null
        val f = Field(name, value(), off, len)
        if (parent == null) tree.add(f) else parent.children.add(f)
        return f
    }

    fun layer(name: String) {
        layers += name
        protocol = name
    }
}

private fun ByteArray.u8(i: Int) = this[i].toInt() and 0xFF
private fun ByteArray.u16(i: Int) = (u8(i) shl 8) or u8(i + 1)
private fun ByteArray.u32(i: Int) = (u16(i).toLong() shl 16) or u16(i + 2).toLong()
private fun ByteArray.hex(off: Int, len: Int, sep: String = "") =
    (off until minOf(size, off + len)).joinToString(sep) { "%02x".format(this[it]) }

object Dissector {
    fun mac(d: ByteArray, o: Int): String {
        val sb = StringBuilder(17)
        for (i in 0 until 6) { if (i > 0) sb.append(':'); val b = d.u8(o + i); sb.append(HEX[b shr 4]).append(HEX[b and 15]) }
        return sb.toString()
    }
    private val HEX = "0123456789abcdef".toCharArray()

    fun ip4(d: ByteArray, o: Int): String = "${d.u8(o)}.${d.u8(o + 1)}.${d.u8(o + 2)}.${d.u8(o + 3)}"
    fun ip6(d: ByteArray, o: Int): String = SystemNet.compactV6(InetAddress.getByAddress(d.copyOfRange(o, o + 16)).hostAddress)

    val SERVICES = mapOf(
        20 to "FTP-data", 21 to "FTP", 22 to "SSH", 23 to "Telnet", 25 to "SMTP", 53 to "DNS", 67 to "DHCP", 68 to "DHCP",
        69 to "TFTP", 80 to "HTTP", 110 to "POP3", 123 to "NTP", 135 to "MS-RPC", 137 to "NetBIOS-NS", 138 to "NetBIOS-DGM",
        139 to "NetBIOS-SSN", 143 to "IMAP", 161 to "SNMP", 162 to "SNMP-trap", 389 to "LDAP", 443 to "HTTPS", 445 to "SMB",
        465 to "SMTPS", 514 to "Syslog", 546 to "DHCPv6", 547 to "DHCPv6", 587 to "SMTP", 631 to "IPP", 636 to "LDAPS",
        853 to "DNS-over-TLS", 993 to "IMAPS", 995 to "POP3S", 1194 to "OpenVPN", 1433 to "MSSQL", 1883 to "MQTT",
        1900 to "SSDP", 3074 to "Xbox Live", 3306 to "MySQL", 3389 to "RDP", 3478 to "STUN", 3479 to "STUN", 3480 to "STUN",
        3702 to "WS-Discovery", 5060 to "SIP", 5222 to "XMPP", 5228 to "Google Push", 5353 to "mDNS", 5355 to "LLMNR",
        5432 to "PostgreSQL", 5900 to "VNC", 6881 to "BitTorrent", 7680 to "Delivery Optimization", 8080 to "HTTP-alt",
        8443 to "HTTPS-alt", 8883 to "MQTT/TLS", 9100 to "Printer", 19302 to "STUN (Google)", 27017 to "MongoDB",
        51820 to "WireGuard", 5223 to "Apple Push", 8009 to "Chromecast", 49152 to "UPnP",
    )

    fun service(port: Int) = SERVICES[port]

    fun dissect(data: ByteArray, linkType: Int, detail: Boolean, frameNo: Long = 0, origLen: Int = data.size, timeText: String = ""): Dissection {
        val d = Dissection(data, detail)
        val frame = d.node(null, "Frame $frameNo", 0, data.size) { "$origLen bytes on wire, ${data.size} bytes captured" }
        d.node(frame, "Arrival time", 0, 0) { timeText }
        d.node(frame, "Frame length", 0, 0) { "$origLen bytes" }
        d.node(frame, "Capture length", 0, 0) { "${data.size} bytes" }
        try {
            when (linkType) {
                Pcap.DLT_EN10MB -> ethernet(d, 0)
                Pcap.DLT_NULL -> {
                    val fam = data.u8(0) or (data.u8(1) shl 8)
                    d.node(null, "Loopback", 0, 4) { "family $fam" }
                    d.layer("Loopback")
                    if (fam == 2) ipv4(d, 4) else if (fam == 24 || fam == 28 || fam == 30) ipv6(d, 4)
                }
                Pcap.DLT_RAW, Pcap.DLT_RAW_ALT, Pcap.DLT_IPV4, Pcap.DLT_IPV6 -> if (data.u8(0) shr 4 == 6) ipv6(d, 0) else ipv4(d, 0)
                Pcap.DLT_LINUX_SLL -> {
                    val type = data.u16(14)
                    d.node(null, "Linux cooked capture", 0, 16) { "protocol 0x%04x".format(type) }
                    etherType(d, type, 16)
                }
                else -> d.info = "Unsupported link type $linkType"
            }
        } catch (e: IndexOutOfBoundsException) {
            d.malformed = true
            d.node(null, "[Malformed or truncated packet]", 0, 0)
            if (d.info.isEmpty()) d.info = "[Malformed packet]"
        }
        if (d.layers.isEmpty()) d.layers += "Frame"
        return d
    }

    // ---------------------------------------------------------------- link layer

    private fun ethernet(d: Dissection, o: Int) {
        val b = d.data
        if (b.size < o + 14) { d.info = "Truncated Ethernet frame"; return }
        d.dstMac = mac(b, o); d.srcMac = mac(b, o + 6)
        d.broadcast = (b.u8(o) and 1) == 1
        var type = b.u16(o + 12)
        var next = o + 14
        val eth = d.node(null, "Ethernet II", o, 14) { "Src: ${d.srcMac}, Dst: ${d.dstMac}" }
        d.node(eth, "Destination", o, 6) { d.dstMac + macNote(b, o) }
        d.node(eth, "Source", o + 6, 6) { d.srcMac + macNote(b, o + 6) }
        d.layer("Ethernet")
        while (type == 0x8100 || type == 0x88A8) {
            val tci = b.u16(next)
            d.node(eth, "802.1Q VLAN", next - 2, 6) { "ID ${tci and 0xFFF}, priority ${tci shr 13}" }
            type = b.u16(next + 2); next += 4
        }
        d.node(eth, "Type", next - 2, 2) { "%s (0x%04x)".format(etherName(type), type) }
        if (type < 0x0600) {
            d.layer(if (b.size > next && b.u8(next) == 0x42) "STP" else "LLC")
            d.info = if (d.protocol == "STP") "Spanning Tree bridge protocol" else "IEEE 802.3 LLC frame"
            d.src = d.srcMac; d.dst = d.dstMac
            return
        }
        etherType(d, type, next)
    }

    private fun macNote(b: ByteArray, o: Int): String = when {
        (0 until 6).all { b.u8(o + it) == 0xFF } -> " (broadcast)"
        b.u8(o) and 1 == 1 -> " (multicast)"
        b.u8(o) and 2 == 2 -> " (locally administered / randomized)"
        else -> ""
    }

    private fun etherName(t: Int) = when (t) {
        0x0800 -> "IPv4"; 0x86DD -> "IPv6"; 0x0806 -> "ARP"; 0x888E -> "EAPOL"; 0x88CC -> "LLDP"
        0x893A -> "IEEE 1905.1"; 0x8899 -> "Realtek"; 0x88E1 -> "HomePlug AV"; 0x8863, 0x8864 -> "PPPoE"; else -> "Unknown"
    }

    private fun etherType(d: Dissection, type: Int, o: Int) {
        when (type) {
            0x0800 -> ipv4(d, o)
            0x86DD -> ipv6(d, o)
            0x0806 -> arp(d, o)
            0x888E -> eapol(d, o)
            0x88CC -> lldp(d, o)
            else -> {
                d.layer(etherName(type).takeIf { it != "Unknown" } ?: "EtherType 0x%04x".format(type))
                d.info = "Ethernet frame, type 0x%04x".format(type)
                d.src = d.srcMac; d.dst = d.dstMac
            }
        }
    }

    private fun arp(d: Dissection, o: Int) {
        val b = d.data
        val op = b.u16(o + 6)
        val sha = mac(b, o + 8); val spa = ip4(b, o + 14)
        val tha = mac(b, o + 18); val tpa = ip4(b, o + 24)
        d.layer("ARP"); d.transport = "ARP"
        d.src = spa; d.dst = tpa
        d.arpIp = spa; d.arpMac = sha
        d.info = when {
            op == 1 && spa == tpa -> "Gratuitous ARP for $spa (announcement)"
            op == 1 && spa == "0.0.0.0" -> "ARP probe: is $tpa in use?"
            op == 1 -> "Who has $tpa? Tell $spa"
            op == 2 -> "$spa is at $sha"
            else -> "ARP opcode $op"
        }
        val n = d.node(null, "Address Resolution Protocol", o, 28) { if (op == 1) "request" else if (op == 2) "reply" else "op $op" }
        d.node(n, "Opcode", o + 6, 2) { if (op == 1) "request (1)" else if (op == 2) "reply (2)" else "$op" }
        d.node(n, "Sender MAC", o + 8, 6) { sha }
        d.node(n, "Sender IP", o + 14, 4) { spa }
        d.node(n, "Target MAC", o + 18, 6) { tha }
        d.node(n, "Target IP", o + 24, 4) { tpa }
    }

    private fun eapol(d: Dissection, o: Int) {
        val b = d.data
        val type = b.u8(o + 1)
        d.layer("EAPOL"); d.src = d.srcMac; d.dst = d.dstMac
        val t = when (type) { 0 -> "EAP packet"; 1 -> "Start"; 2 -> "Logoff"; 3 -> "Key (Wi-Fi handshake)"; else -> "type $type" }
        d.info = "EAPOL $t"
        d.node(null, "802.1X Authentication", o, 4 + b.u16(o + 2)) { t }
    }

    private fun lldp(d: Dissection, o: Int) {
        val b = d.data
        d.layer("LLDP"); d.src = d.srcMac; d.dst = d.dstMac
        val n = d.node(null, "Link Layer Discovery Protocol", o, b.size - o)
        var p = o
        val parts = mutableListOf<String>()
        while (p + 2 <= b.size) {
            val h = b.u16(p); val type = h shr 9; val len = h and 0x1FF
            if (type == 0 || p + 2 + len > b.size) break
            val text = String(b, p + 2, len, Charsets.UTF_8).filter { it >= ' ' }
            when (type) {
                5 -> { d.selfName = text; parts += "System: $text"; d.node(n, "System name", p, len + 2) { text } }
                6 -> { d.deviceInfo = text; d.node(n, "System description", p, len + 2) { text } }
                4 -> d.node(n, "Port description", p, len + 2) { text }
                else -> d.node(n, "TLV type $type", p, len + 2) { "$len bytes" }
            }
            p += 2 + len
        }
        d.info = "LLDP " + parts.joinToString().ifEmpty { "announcement" }
    }

    // ---------------------------------------------------------------- network layer

    private fun ipv4(d: Dissection, o: Int) {
        val b = d.data
        val ihl = (b.u8(o) and 0x0F) * 4
        val total = b.u16(o + 2)
        val flagsFrag = b.u16(o + 6)
        val proto = b.u8(o + 9)
        d.src = ip4(b, o + 12); d.dst = ip4(b, o + 16)
        d.ttl = b.u8(o + 8)
        d.layer("IPv4")
        if (d.dst == "255.255.255.255" || d.dst!!.startsWith("224.") || d.dst!!.startsWith("239.") || d.dst!!.endsWith(".255")) d.broadcast = true
        val n = d.node(null, "Internet Protocol Version 4", o, ihl) { "Src: ${d.src}, Dst: ${d.dst}" }
        d.node(n, "Header length", o, 1) { "$ihl bytes" }
        d.node(n, "Differentiated services", o + 1, 1) { "DSCP ${b.u8(o + 1) shr 2}, ECN ${b.u8(o + 1) and 3}" }
        d.node(n, "Total length", o + 2, 2) { "$total" }
        d.node(n, "Identification", o + 4, 2) { "0x%04x (%d)".format(b.u16(o + 4), b.u16(o + 4)) }
        d.node(n, "Flags", o + 6, 1) {
            listOfNotNull("Don't fragment".takeIf { flagsFrag and 0x4000 != 0 }, "More fragments".takeIf { flagsFrag and 0x2000 != 0 })
                .joinToString().ifEmpty { "none" }
        }
        d.node(n, "Fragment offset", o + 6, 2) { "${(flagsFrag and 0x1FFF) * 8}" }
        d.node(n, "Time to live", o + 8, 1) { "${d.ttl}" }
        d.node(n, "Protocol", o + 9, 1) { "${ipProtoName(proto)} ($proto)" }
        d.node(n, "Header checksum", o + 10, 2) { "0x%04x".format(b.u16(o + 10)) }
        d.node(n, "Source address", o + 12, 4) { d.src!! }
        d.node(n, "Destination address", o + 16, 4) { d.dst!! }
        if (ihl > 20) d.node(n, "Options", o + 20, ihl - 20) { "${ihl - 20} bytes" }
        val end = minOf(b.size, o + maxOf(total, ihl))
        if ((flagsFrag and 0x1FFF) != 0) {
            d.layer("IPv4 fragment")
            d.info = "Fragment of IP packet (offset ${(flagsFrag and 0x1FFF) * 8}, id 0x%04x)".format(b.u16(o + 4))
            return
        }
        transport(d, proto, o + ihl, end)
    }

    private fun ipv6(d: Dissection, o: Int) {
        val b = d.data
        val plen = b.u16(o + 4)
        var next = b.u8(o + 6)
        d.src = ip6(b, o + 8); d.dst = ip6(b, o + 24)
        d.ttl = b.u8(o + 7)
        d.layer("IPv6")
        if (d.dst!!.startsWith("ff")) d.broadcast = true
        val n = d.node(null, "Internet Protocol Version 6", o, 40) { "Src: ${d.src}, Dst: ${d.dst}" }
        d.node(n, "Traffic class", o, 2) { "0x%02x".format((b.u16(o) shr 4) and 0xFF) }
        d.node(n, "Flow label", o + 1, 3) { "0x%05x".format(b.u32(o) and 0xFFFFF) }
        d.node(n, "Payload length", o + 4, 2) { "$plen" }
        d.node(n, "Next header", o + 6, 1) { "${ipProtoName(next)} ($next)" }
        d.node(n, "Hop limit", o + 7, 1) { "${d.ttl}" }
        d.node(n, "Source address", o + 8, 16) { d.src!! + v6Note(d.src!!) }
        d.node(n, "Destination address", o + 24, 16) { d.dst!! + v6Note(d.dst!!) }
        var p = o + 40
        val end = minOf(b.size, o + 40 + plen)
        var guard = 0
        while (next in setOf(0, 43, 60, 44) && guard++ < 8 && p + 8 <= end) {
            val len = if (next == 44) 8 else (b.u8(p + 1) + 1) * 8
            d.node(n, "Extension header", p, len) { ipProtoName(next) }
            next = b.u8(p); p += len
        }
        transport(d, next, p, end)
    }

    private fun v6Note(a: String) = when {
        a.startsWith("fe80") -> " (link-local)"
        a.startsWith("ff") -> " (multicast)"
        a.startsWith("fd") || a.startsWith("fc") -> " (unique local)"
        else -> ""
    }

    private fun ipProtoName(p: Int) = when (p) {
        0 -> "Hop-by-hop options"; 1 -> "ICMP"; 2 -> "IGMP"; 6 -> "TCP"; 17 -> "UDP"; 41 -> "IPv6"; 43 -> "Routing"
        44 -> "Fragment"; 47 -> "GRE"; 50 -> "ESP"; 51 -> "AH"; 58 -> "ICMPv6"; 60 -> "Destination options"; 132 -> "SCTP"
        else -> "Protocol $p"
    }

    private fun transport(d: Dissection, proto: Int, o: Int, end: Int) {
        when (proto) {
            6 -> tcp(d, o, end)
            17 -> udp(d, o, end)
            1 -> icmp(d, o, end)
            58 -> icmp6(d, o, end)
            2 -> igmp(d, o)
            else -> {
                d.layer(ipProtoName(proto)); d.transport = ipProtoName(proto)
                d.info = "${ipProtoName(proto)} packet, ${end - o} bytes"
            }
        }
    }

    // ---------------------------------------------------------------- ICMP

    private fun icmp(d: Dissection, o: Int, end: Int) {
        val b = d.data
        val type = b.u8(o); val code = b.u8(o + 1)
        d.layer("ICMP"); d.transport = "ICMP"
        val name = when (type) {
            0 -> "Echo (ping) reply"; 3 -> "Destination unreachable (${unreachCode(code)})"; 4 -> "Source quench"
            5 -> "Redirect"; 8 -> "Echo (ping) request"; 9 -> "Router advertisement"; 10 -> "Router solicitation"
            11 -> if (code == 0) "Time-to-live exceeded in transit" else "Fragment reassembly time exceeded"
            12 -> "Parameter problem"; 13 -> "Timestamp request"; 14 -> "Timestamp reply"; else -> "Type $type code $code"
        }
        val n = d.node(null, "Internet Control Message Protocol", o, end - o) { name }
        d.node(n, "Type", o, 1) { "$type" }
        d.node(n, "Code", o + 1, 1) { "$code" }
        d.node(n, "Checksum", o + 2, 2) { "0x%04x".format(b.u16(o + 2)) }
        d.info = name
        if (type == 0 || type == 8) {
            d.node(n, "Identifier", o + 4, 2) { "${b.u16(o + 4)}" }
            d.node(n, "Sequence", o + 6, 2) { "${b.u16(o + 6)}" }
            d.node(n, "Data", o + 8, end - o - 8) { "${end - o - 8} bytes" }
            d.info += "  id=%d, seq=%d, ttl=%d".format(b.u16(o + 4), b.u16(o + 6), d.ttl)
        }
        if (type == 3 || type == 11 || type == 12) {
            d.problem = if (type == 11) "ICMP time exceeded" else "ICMP error: $name"
            if (end - o >= 28 && (b.u8(o + 8) shr 4) == 4) {
                val inner = o + 8
                val ihl = (b.u8(inner) and 15) * 4
                val proto = b.u8(inner + 9)
                val s = ip4(b, inner + 12); val t = ip4(b, inner + 16)
                val ports = if ((proto == 6 || proto == 17) && inner + ihl + 4 <= end) ":${b.u16(inner + ihl)} → $t:${b.u16(inner + ihl + 2)}" else " → $t"
                d.node(n, "Original packet", inner, end - inner) { "${ipProtoName(proto)} $s$ports" }
                d.info += "  (for ${ipProtoName(proto)} $s$ports)"
            }
        }
    }

    private fun unreachCode(c: Int) = when (c) {
        0 -> "network unreachable"; 1 -> "host unreachable"; 2 -> "protocol unreachable"; 3 -> "port unreachable"
        4 -> "fragmentation needed"; 9, 10, 13 -> "administratively prohibited"; else -> "code $c"
    }

    private fun icmp6(d: Dissection, o: Int, end: Int) {
        val b = d.data
        val type = b.u8(o); val code = b.u8(o + 1)
        d.layer("ICMPv6"); d.transport = "ICMPv6"
        var name = when (type) {
            1 -> "Destination unreachable"; 2 -> "Packet too big"; 3 -> "Time exceeded"; 4 -> "Parameter problem"
            128 -> "Echo (ping) request"; 129 -> "Echo (ping) reply"; 130 -> "Multicast listener query"
            131, 143 -> "Multicast listener report"; 133 -> "Router solicitation"; 134 -> "Router advertisement"
            135 -> "Neighbor solicitation"; 136 -> "Neighbor advertisement"; 137 -> "Redirect"; else -> "Type $type code $code"
        }
        if ((type == 135 || type == 136) && end - o >= 24) name += " for ${ip6(b, o + 8)}"
        if (type in 1..4) d.problem = "ICMPv6 error: $name"
        d.info = name
        val n = d.node(null, "Internet Control Message Protocol v6", o, end - o) { name }
        d.node(n, "Type", o, 1) { "$type" }
        d.node(n, "Code", o + 1, 1) { "$code" }
        if (type == 128 || type == 129) {
            d.node(n, "Identifier", o + 4, 2) { "${b.u16(o + 4)}" }
            d.node(n, "Sequence", o + 6, 2) { "${b.u16(o + 6)}" }
        }
        if ((type == 135 || type == 136) && end - o >= 24) d.node(n, "Target address", o + 8, 16) { ip6(b, o + 8) }
        if (type == 134) d.node(n, "Router lifetime", o + 6, 2) { "${b.u16(o + 6)} s" }
    }

    private fun igmp(d: Dissection, o: Int) {
        val b = d.data
        val type = b.u8(o)
        d.layer("IGMP"); d.transport = "IGMP"
        d.info = when (type) {
            0x11 -> "Membership query"; 0x12, 0x16 -> "Membership report group ${ip4(b, o + 4)}"; 0x22 -> "Membership report (v3)"
            0x17 -> "Leave group ${ip4(b, o + 4)}"; else -> "IGMP type 0x%02x".format(type)
        }
        d.node(null, "Internet Group Management Protocol", o, 8) { d.info }
    }

    // ---------------------------------------------------------------- transport

    const val FIN = 1; const val SYN = 2; const val RST = 4; const val PSH = 8; const val ACK = 16; const val URG = 32

    fun flagNames(f: Int) = listOfNotNull(
        "SYN".takeIf { f and SYN != 0 }, "FIN".takeIf { f and FIN != 0 }, "RST".takeIf { f and RST != 0 },
        "PSH".takeIf { f and PSH != 0 }, "ACK".takeIf { f and ACK != 0 }, "URG".takeIf { f and URG != 0 },
        "ECE".takeIf { f and 64 != 0 }, "CWR".takeIf { f and 128 != 0 },
    ).joinToString(", ")

    private fun tcp(d: Dissection, o: Int, end: Int) {
        val b = d.data
        d.srcPort = b.u16(o); d.dstPort = b.u16(o + 2)
        d.tcpSeq = b.u32(o + 4); d.tcpAck = b.u32(o + 8)
        val hlen = (b.u8(o + 12) shr 4) * 4
        d.tcpFlags = b.u8(o + 13)
        d.tcpWindow = b.u16(o + 14)
        d.layer("TCP"); d.transport = "TCP"
        d.payloadOffset = o + hlen
        d.payloadLength = maxOf(0, end - d.payloadOffset)
        val n = d.node(null, "Transmission Control Protocol", o, hlen) { "Src Port: ${d.srcPort}, Dst Port: ${d.dstPort}, Len: ${d.payloadLength}" }
        d.node(n, "Source port", o, 2) { portText(d.srcPort) }
        d.node(n, "Destination port", o + 2, 2) { portText(d.dstPort) }
        d.node(n, "Sequence number (raw)", o + 4, 4) { "${d.tcpSeq}" }
        d.node(n, "Acknowledgment number (raw)", o + 8, 4) { "${d.tcpAck}" }
        d.node(n, "Header length", o + 12, 1) { "$hlen bytes" }
        d.node(n, "Flags", o + 13, 1) { "0x%03x (%s)".format(d.tcpFlags, flagNames(d.tcpFlags)) }
        d.node(n, "Window", o + 14, 2) { "${d.tcpWindow}" }
        d.node(n, "Checksum", o + 16, 2) { "0x%04x".format(b.u16(o + 16)) }
        val opts = mutableListOf<String>()
        if (hlen > 20) {
            val on = d.node(n, "Options", o + 20, hlen - 20) { "${hlen - 20} bytes" }
            var p = o + 20
            while (p < o + hlen && p < b.size) {
                val kind = b.u8(p)
                if (kind == 0) break
                if (kind == 1) { p++; continue }
                val len = b.u8(p + 1).coerceAtLeast(2)
                val text = when (kind) {
                    2 -> "MSS=${b.u16(p + 2)}"; 3 -> "WS=${1 shl b.u8(p + 2)}"; 4 -> "SACK_PERM"
                    5 -> "SACK"; 8 -> "TSval=${b.u32(p + 2)} TSecr=${b.u32(p + 6)}"; else -> "kind $kind"
                }
                if (kind != 8 && kind != 5) opts += text
                d.node(on, "Option", p, len) { text }
                p += len
            }
        }
        d.node(n, "Payload", d.payloadOffset, d.payloadLength) { "${d.payloadLength} bytes" }
        d.info = "${d.srcPort} → ${d.dstPort} [${flagNames(d.tcpFlags)}] Win=${d.tcpWindow} Len=${d.payloadLength}" +
            if (opts.isNotEmpty()) " " + opts.joinToString(" ") else ""
        if (d.tcpFlags and RST != 0) d.problem = "Connection reset (RST)"
        if (d.tcpWindow == 0 && d.tcpFlags and (SYN or RST or FIN) == 0) d.problem = "TCP zero window (receiver is full)"
        if (d.payloadLength > 0) tcpPayload(d, d.payloadOffset, end)
    }

    private fun portText(p: Int) = service(p)?.let { "$p ($it)" } ?: "$p"

    private fun tcpPayload(d: Dissection, o: Int, end: Int) {
        val b = d.data
        val ports = setOf(d.srcPort, d.dstPort)
        val first = b.u8(o)
        when {
            first in 20..23 && end - o >= 5 && b.u8(o + 1) == 3 -> tls(d, o, end)
            startsWithText(b, o, end, "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "HTTP/1.") -> httpText(d, o, end, "HTTP")
            startsWithText(b, o, end, "SSH-") -> {
                d.layer("SSH"); val line = textLine(b, o, end); d.info = "SSH banner: $line"
                d.node(null, "SSH Protocol", o, end - o) { line }
            }
            53 in ports && end - o > 14 -> dns(d, o + 2, end, "DNS")
            else -> {
                val svc = ports.mapNotNull { SERVICES[it] }.firstOrNull()
                if (svc != null && svc != "HTTPS") {
                    d.layer(svc)
                    d.node(null, svc, o, end - o) { "${end - o} bytes of application data" }
                }
            }
        }
    }

    private fun udp(d: Dissection, o: Int, end: Int) {
        val b = d.data
        d.srcPort = b.u16(o); d.dstPort = b.u16(o + 2)
        val len = b.u16(o + 4)
        d.layer("UDP"); d.transport = "UDP"
        val pend = minOf(end, o + maxOf(len, 8))
        d.payloadOffset = o + 8
        d.payloadLength = maxOf(0, pend - d.payloadOffset)
        val n = d.node(null, "User Datagram Protocol", o, 8) { "Src Port: ${d.srcPort}, Dst Port: ${d.dstPort}" }
        d.node(n, "Source port", o, 2) { portText(d.srcPort) }
        d.node(n, "Destination port", o + 2, 2) { portText(d.dstPort) }
        d.node(n, "Length", o + 4, 2) { "$len" }
        d.node(n, "Checksum", o + 6, 2) { "0x%04x".format(b.u16(o + 6)) }
        d.node(n, "Payload", d.payloadOffset, d.payloadLength) { "${d.payloadLength} bytes" }
        d.info = "${d.srcPort} → ${d.dstPort} Len=${d.payloadLength}"
        if (d.payloadLength == 0) return
        val p = o + 8
        val ports = setOf(d.srcPort, d.dstPort)
        when {
            5353 in ports -> dns(d, p, pend, "mDNS")
            5355 in ports -> dns(d, p, pend, "LLMNR")
            53 in ports -> dns(d, p, pend, "DNS")
            137 in ports -> nbns(d, p, pend)
            67 in ports || 68 in ports -> dhcp(d, p, pend)
            123 in ports -> ntp(d, p, pend)
            1900 in ports || 3702 in ports -> httpText(d, p, pend, if (1900 in ports) "SSDP" else "WS-Discovery")
            pend - p >= 20 && b.u32(p + 4) == 0x2112A442L -> stun(d, p, pend)
            (443 in ports || 80 in ports) && quic(d, p, pend) -> Unit
            else -> ports.mapNotNull { SERVICES[it] }.firstOrNull()?.let { svc ->
                d.layer(svc)
                d.node(null, svc, p, pend - p) { "${pend - p} bytes" }
            }
        }
    }

    // ---------------------------------------------------------------- application layer

    private fun startsWithText(b: ByteArray, o: Int, end: Int, vararg prefixes: String) = prefixes.any { pre ->
        end - o >= pre.length && pre.indices.all { b[o + it].toInt().toChar() == pre[it] }
    }

    private fun textLine(b: ByteArray, o: Int, end: Int): String {
        var e = o
        while (e < end && e - o < 300 && b[e] != '\r'.code.toByte() && b[e] != '\n'.code.toByte()) e++
        return String(b, o, e - o, Charsets.ISO_8859_1)
    }

    private fun httpText(d: Dissection, o: Int, end: Int, proto: String) {
        val b = d.data
        val text = String(b, o, minOf(end - o, 4096), Charsets.ISO_8859_1)
        val headerEnd = text.indexOf("\r\n\r\n").let { if (it < 0) text.length else it }
        val lines = text.substring(0, headerEnd).split("\r\n", "\n")
        d.layer(proto)
        d.info = lines.firstOrNull().orEmpty()
        val n = d.node(null, if (proto == "HTTP") "Hypertext Transfer Protocol" else proto, o, end - o) { lines.firstOrNull().orEmpty() }
        var off = o
        for (line in lines) {
            d.node(n, line.substringBefore(':', line).take(60), off, line.length + 2) { if (line.contains(':')) line.substringAfter(':').trim() else "" }
            off += line.length + 2
            val key = line.substringBefore(':').trim().lowercase()
            val value = line.substringAfter(':', "").trim()
            when (key) {
                "host" -> if (proto == "HTTP" && d.dst != null) d.names += d.dst!! to value.substringBefore(':')
                "server" -> if (proto != "HTTP") d.deviceInfo = value
            }
        }
        if (headerEnd + 4 < text.length) d.node(n, "Body", o + headerEnd + 4, end - o - headerEnd - 4) { "${end - o - headerEnd - 4} bytes" }
        if (proto == "HTTP" && d.info.startsWith("HTTP/1.")) {
            val status = d.info.split(' ').getOrNull(1)?.toIntOrNull()
            if (status != null && status >= 500) d.problem = "HTTP server error $status"
        }
    }

    // DNS, mDNS, LLMNR ------------------------------------------------

    private val DNS_TYPES = mapOf(1 to "A", 2 to "NS", 5 to "CNAME", 6 to "SOA", 12 to "PTR", 13 to "HINFO", 15 to "MX",
        16 to "TXT", 28 to "AAAA", 33 to "SRV", 41 to "OPT", 47 to "NSEC", 64 to "SVCB", 65 to "HTTPS", 255 to "ANY")
    private val RCODES = mapOf(0 to "No error", 1 to "Format error", 2 to "Server failure", 3 to "No such name",
        4 to "Not implemented", 5 to "Refused")

    private fun dnsName(b: ByteArray, start: Int, base: Int, end: Int): Pair<String, Int> {
        val sb = StringBuilder()
        var p = start; var next = -1; var jumps = 0
        while (p < end) {
            val len = b.u8(p)
            when {
                len == 0 -> { p++; break }
                len and 0xC0 == 0xC0 -> {
                    if (next < 0) next = p + 2
                    p = base + (((len and 0x3F) shl 8) or b.u8(p + 1))
                    if (++jumps > 20) break
                }
                else -> {
                    if (sb.isNotEmpty()) sb.append('.')
                    for (i in 1..len) { val c = b.u8(p + i); sb.append(if (c in 33..126) c.toChar() else '?') }
                    p += len + 1
                }
            }
        }
        return sb.toString().ifEmpty { "<Root>" } to (if (next >= 0) next else p)
    }

    private fun dns(d: Dissection, o: Int, end: Int, proto: String) {
        val b = d.data
        if (end - o < 12) return
        val id = b.u16(o); val flags = b.u16(o + 2)
        val qd = b.u16(o + 4); val an = b.u16(o + 6); val ns = b.u16(o + 8); val ar = b.u16(o + 10)
        val response = flags and 0x8000 != 0
        val rcode = flags and 0xF
        d.layer(proto)
        val n = d.node(null, when (proto) { "mDNS" -> "Multicast Domain Name System"; "LLMNR" -> "Link-local Multicast Name Resolution"; else -> "Domain Name System" } +
            if (response) " (response)" else " (query)", o, end - o)
        d.node(n, "Transaction ID", o, 2) { "0x%04x".format(id) }
        val fn = d.node(n, "Flags", o + 2, 2) { "0x%04x %s".format(flags, if (response) "Standard query response" else "Standard query") }
        d.node(fn, "Recursion desired", o + 2, 2) { if (flags and 0x100 != 0) "yes" else "no" }
        if (response) {
            d.node(fn, "Authoritative", o + 2, 2) { if (flags and 0x400 != 0) "yes" else "no" }
            d.node(fn, "Truncated", o + 2, 2) { if (flags and 0x200 != 0) "yes" else "no" }
            d.node(fn, "Recursion available", o + 2, 2) { if (flags and 0x80 != 0) "yes" else "no" }
            d.node(fn, "Reply code", o + 3, 1) { "${RCODES[rcode] ?: "code $rcode"} ($rcode)" }
        }
        d.node(n, "Questions", o + 4, 2) { "$qd" }
        d.node(n, "Answer RRs", o + 6, 2) { "$an" }
        d.node(n, "Authority RRs", o + 8, 2) { "$ns" }
        d.node(n, "Additional RRs", o + 10, 2) { "$ar" }
        var p = o + 12
        val questions = mutableListOf<String>()
        val qn = if (qd > 0) d.node(n, "Queries", p, 0) else null
        repeat(minOf(qd, 50)) {
            val (name, np) = dnsName(b, p, o, end)
            val type = b.u16(np)
            val t = DNS_TYPES[type] ?: "type $type"
            d.node(qn, name, p, np + 4 - p) { "type $t, class ${if (b.u16(np + 2) and 0x7FFF == 1) "IN" else "0x%04x".format(b.u16(np + 2))}" }
            questions += "$t $name"
            p = np + 4
        }
        val answers = mutableListOf<String>()
        val firstQ = questions.firstOrNull()?.substringAfter(' ')
        for ((section, count) in listOf("Answers" to an, "Authoritative nameservers" to ns, "Additional records" to ar)) {
            if (count == 0) continue
            val sn = d.node(n, section, p, 0)
            repeat(minOf(count, 100)) {
                if (p >= end) return@repeat
                val (name, np) = dnsName(b, p, o, end)
                val type = b.u16(np); val ttl = b.u32(np + 4); val rdlen = b.u16(np + 8)
                val rd = np + 10
                val t = DNS_TYPES[type] ?: "type $type"
                val value = when (type) {
                    1 -> ip4(b, rd)
                    28 -> ip6(b, rd)
                    2, 5, 12 -> dnsName(b, rd, o, end).first
                    15 -> "pref ${b.u16(rd)} ${dnsName(b, rd + 2, o, end).first}"
                    33 -> "prio ${b.u16(rd)} weight ${b.u16(rd + 2)} port ${b.u16(rd + 4)} ${dnsName(b, rd + 6, o, end).first}"
                    16 -> txt(b, rd, rd + rdlen)
                    64, 65 -> "priority ${b.u16(rd)} target ${dnsName(b, rd + 2, o, end).first}"
                    41 -> "EDNS UDP payload size ${b.u16(np + 2)}"
                    else -> "$rdlen bytes"
                }
                d.node(sn, name, p, rd + rdlen - p) { "type $t, ttl $ttl, $value" }
                if (section == "Answers" || proto != "DNS") {
                    if (type == 1 || type == 28) {
                        d.names += value to (if (proto == "DNS" && firstQ != null) firstQ else name)
                        if (proto == "mDNS" && value == d.src && name.endsWith(".local")) d.selfName = name.removeSuffix(".local")
                    }
                    if (section == "Answers" && type != 41) answers += "$t $value"
                }
                p = rd + rdlen
            }
        }
        val kind = if (response) "Standard query response" else "Standard query"
        d.info = "$kind 0x%04x %s".format(id, questions.joinToString(", ")) +
            (if (answers.isNotEmpty()) "  → " + answers.take(4).joinToString(", ") + (if (answers.size > 4) " …" else "") else "") +
            (if (response && rcode != 0) "  [${RCODES[rcode] ?: "rcode $rcode"}]" else "")
        if (proto == "mDNS" && !response && questions.isEmpty() && answers.isNotEmpty()) d.info = "mDNS announcement: " + answers.take(3).joinToString()
        if (response && (rcode == 2 || rcode == 5)) d.problem = "DNS ${RCODES[rcode]}"
    }

    private fun txt(b: ByteArray, s: Int, e: Int): String {
        val parts = mutableListOf<String>(); var p = s
        while (p < e && parts.size < 8) { val l = b.u8(p); parts += String(b, p + 1, minOf(l, e - p - 1), Charsets.UTF_8); p += l + 1 }
        return parts.joinToString(" | ") { "\"$it\"" }
    }

    private fun nbns(d: Dissection, o: Int, end: Int) {
        val b = d.data
        d.layer("NetBIOS-NS")
        val flags = b.u16(o + 2)
        val op = (flags shr 11) and 0xF
        var name = ""
        if (end - o > 13 + 32 && b.u8(o + 12) == 32) {
            val sb = StringBuilder()
            for (i in 0 until 16) sb.append((((b.u8(o + 13 + i * 2) - 'A'.code) shl 4) or (b.u8(o + 14 + i * 2) - 'A'.code)).toChar())
            name = sb.toString().substring(0, 15).trim()
        }
        val kind = when (op) { 0 -> "Name query"; 5 -> "Registration"; 6 -> "Release"; 8 -> "Refresh"; else -> "Opcode $op" }
        d.info = "NetBIOS $kind $name" + if (flags and 0x8000 != 0) " (response)" else ""
        if (op == 5 || op == 8) d.selfName = name
        d.node(null, "NetBIOS Name Service", o, end - o) { d.info }
    }

    // DHCP ----------------------------------------------------------

    private fun dhcp(d: Dissection, o: Int, end: Int) {
        val b = d.data
        if (end - o < 240) { d.layer("DHCP"); d.info = "DHCP (truncated)"; return }
        val op = b.u8(o)
        val xid = b.u32(o + 4)
        val ciaddr = ip4(b, o + 12); val yiaddr = ip4(b, o + 16); val siaddr = ip4(b, o + 20)
        val chaddr = mac(b, o + 28)
        d.layer("DHCP")
        val n = d.node(null, "Dynamic Host Configuration Protocol", o, end - o)
        d.node(n, "Message type", o, 1) { if (op == 1) "Boot request (1)" else "Boot reply (2)" }
        d.node(n, "Transaction ID", o + 4, 4) { "0x%08x".format(xid) }
        d.node(n, "Client IP address", o + 12, 4) { ciaddr }
        d.node(n, "Your (client) IP address", o + 16, 4) { yiaddr }
        d.node(n, "Next server IP address", o + 20, 4) { siaddr }
        d.node(n, "Client MAC address", o + 28, 6) { chaddr }
        var msgType = ""
        var p = o + 240
        val on = d.node(n, "Options", p, end - p)
        var hostname: String? = null
        var requested: String? = null
        while (p < end) {
            val code = b.u8(p)
            if (code == 255) { d.node(on, "End", p, 1); break }
            if (code == 0) { p++; continue }
            val len = b.u8(p + 1)
            val v = p + 2
            val (label, value) = when (code) {
                53 -> "DHCP message type" to when (b.u8(v)) {
                    1 -> "Discover"; 2 -> "Offer"; 3 -> "Request"; 4 -> "Decline"; 5 -> "ACK"; 6 -> "NAK"; 7 -> "Release"; 8 -> "Inform"; else -> "${b.u8(v)}"
                }.also { msgType = it }
                1 -> "Subnet mask" to ip4(b, v)
                3 -> "Router" to (0 until len / 4).joinToString { ip4(b, v + it * 4) }
                6 -> "DNS servers" to (0 until len / 4).joinToString { ip4(b, v + it * 4) }
                12 -> "Host name" to String(b, v, len, Charsets.UTF_8).also { hostname = it }
                15 -> "Domain name" to String(b, v, len, Charsets.UTF_8)
                50 -> "Requested IP address" to ip4(b, v).also { requested = it }
                51 -> "Lease time" to "${b.u32(v)} s (${b.u32(v) / 3600} h)"
                54 -> "DHCP server" to ip4(b, v)
                55 -> "Parameter request list" to "$len items"
                60 -> "Vendor class" to String(b, v, len, Charsets.UTF_8).also { d.deviceInfo = it }
                61 -> "Client identifier" to b.hex(v, len, ":")
                81 -> "Client FQDN" to String(b, v + 3, maxOf(0, len - 3), Charsets.UTF_8).filter { it >= ' ' }
                else -> "Option $code" to "$len bytes"
            }
            d.node(on, label, p, len + 2) { value }
            p += len + 2
        }
        if (hostname != null) d.selfName = hostname
        if (msgType == "NAK") d.problem = "DHCP NAK (address refused)"
        d.info = "DHCP $msgType - Transaction ID 0x%08x".format(xid) +
            (requested?.let { " requesting $it" } ?: "") +
            (if (yiaddr != "0.0.0.0") " assigning $yiaddr" else "") +
            (hostname?.let { " ($it)" } ?: "") + " for $chaddr"
        d.arpMac = chaddr
        if (yiaddr != "0.0.0.0" && (msgType == "ACK")) d.arpIp = yiaddr
    }

    private fun ntp(d: Dissection, o: Int, end: Int) {
        val b = d.data
        d.layer("NTP")
        if (end - o < 48) { d.info = "NTP"; return }
        val li = b.u8(o)
        val version = (li shr 3) and 7; val mode = li and 7
        val stratum = b.u8(o + 1)
        val modeName = when (mode) { 1 -> "symmetric active"; 3 -> "client"; 4 -> "server"; 5 -> "broadcast"; else -> "mode $mode" }
        d.info = "NTP Version $version, $modeName" + if (mode == 4) ", stratum $stratum" else ""
        val n = d.node(null, "Network Time Protocol", o, end - o) { modeName }
        d.node(n, "Version", o, 1) { "$version" }
        d.node(n, "Mode", o, 1) { modeName }
        d.node(n, "Stratum", o + 1, 1) { "$stratum" }
        val sec = b.u32(o + 40) - 2208988800L
        d.node(n, "Transmit timestamp", o + 40, 8) { if (sec > 0) java.util.Date(sec * 1000).toString() else "0" }
    }

    private fun stun(d: Dissection, o: Int, end: Int) {
        val b = d.data
        val type = b.u16(o)
        d.layer("STUN")
        val name = when (type) { 0x0001 -> "Binding Request"; 0x0101 -> "Binding Success Response"; 0x0111 -> "Binding Error Response"; else -> "Message 0x%04x".format(type) }
        val n = d.node(null, "Session Traversal Utilities for NAT", o, end - o) { name }
        d.node(n, "Transaction ID", o + 8, 12) { b.hex(o + 8, 12) }
        var p = o + 20
        var mapped = ""
        while (p + 4 <= end) {
            val at = b.u16(p); val al = b.u16(p + 2)
            if (at == 0x0020 && al >= 8 && b.u8(p + 5) == 1) {
                val port = b.u16(p + 6) xor 0x2112
                val ip = "${b.u8(p + 8) xor 0x21}.${b.u8(p + 9) xor 0x12}.${b.u8(p + 10) xor 0xA4}.${b.u8(p + 11) xor 0x42}"
                mapped = "$ip:$port"
                d.node(n, "XOR-MAPPED-ADDRESS (your public address)", p, al + 4) { mapped }
            } else d.node(n, "Attribute 0x%04x".format(at), p, al + 4) { "$al bytes" }
            p += 4 + (al + 3) / 4 * 4
        }
        d.info = "STUN $name" + if (mapped.isNotEmpty()) " (public address $mapped)" else ""
    }

    private fun quic(d: Dissection, o: Int, end: Int): Boolean {
        val b = d.data
        if (end - o < 7) return false
        val first = b.u8(o)
        if (first and 0x80 != 0) {
            val version = b.u32(o + 1)
            val known = version == 1L || version == 0x6b3343cfL || version == 0L || (version shr 8) == 0xff0000L
            if (!known) return false
            val dcidLen = b.u8(o + 5)
            val type = if (version == 0x6b3343cfL) listOf("Retry", "Initial", "0-RTT", "Handshake")[(first shr 4) and 3]
            else listOf("Initial", "0-RTT", "Handshake", "Retry")[(first shr 4) and 3]
            d.layer("QUIC")
            d.info = if (version == 0L) "QUIC Version Negotiation" else "QUIC $type, DCID=${b.hex(o + 6, dcidLen)}"
            val n = d.node(null, "QUIC IETF", o, end - o) { if (version == 0L) "Version Negotiation" else "Long header, $type" }
            d.node(n, "Version", o + 1, 4) { "0x%08x".format(version) }
            d.node(n, "Destination connection ID", o + 6, dcidLen) { b.hex(o + 6, dcidLen) }
            d.node(n, "Protected payload", o + 6 + dcidLen, end - o - 6 - dcidLen) { "${end - o - 6 - dcidLen} bytes (encrypted)" }
            return true
        }
        if (first and 0x40 != 0 && (d.srcPort == 443 || d.dstPort == 443)) {
            d.layer("QUIC")
            d.info = "QUIC protected payload (${end - o} bytes)"
            d.node(null, "QUIC IETF", o, end - o) { "Short header, encrypted application data" }
            return true
        }
        return false
    }

    // TLS -----------------------------------------------------------

    private val CIPHERS = mapOf(0x1301 to "TLS_AES_128_GCM_SHA256", 0x1302 to "TLS_AES_256_GCM_SHA384",
        0x1303 to "TLS_CHACHA20_POLY1305_SHA256", 0xC02B to "ECDHE_ECDSA_AES_128_GCM_SHA256", 0xC02F to "ECDHE_RSA_AES_128_GCM_SHA256",
        0xC02C to "ECDHE_ECDSA_AES_256_GCM_SHA384", 0xC030 to "ECDHE_RSA_AES_256_GCM_SHA384", 0xCCA8 to "ECDHE_RSA_CHACHA20_POLY1305",
        0xCCA9 to "ECDHE_ECDSA_CHACHA20_POLY1305", 0x009C to "RSA_AES_128_GCM_SHA256", 0x002F to "RSA_AES_128_CBC_SHA")

    private fun tlsVersion(v: Int) = when (v) {
        0x0300 -> "SSL 3.0"; 0x0301 -> "TLS 1.0"; 0x0302 -> "TLS 1.1"; 0x0303 -> "TLS 1.2"; 0x0304 -> "TLS 1.3"; else -> "0x%04x".format(v)
    }

    private val ALERTS = mapOf(0 to "close notify", 10 to "unexpected message", 20 to "bad record MAC", 40 to "handshake failure",
        42 to "bad certificate", 43 to "unsupported certificate", 44 to "certificate revoked", 45 to "certificate expired",
        46 to "certificate unknown", 47 to "illegal parameter", 48 to "unknown CA", 50 to "decode error", 51 to "decrypt error",
        70 to "protocol version", 71 to "insufficient security", 80 to "internal error", 90 to "user canceled",
        112 to "unrecognized name", 116 to "certificate required", 120 to "no application protocol")

    private fun tls(d: Dissection, o: Int, end: Int) {
        val b = d.data
        var p = o
        val infos = mutableListOf<String>()
        var label = "TLS"
        val top = d.node(null, "Transport Layer Security", o, end - o)
        while (p + 5 <= end) {
            val ct = b.u8(p); val ver = b.u16(p + 1); val len = b.u16(p + 3)
            if (ct !in 20..23 || b.u8(p + 1) != 3) break
            val body = p + 5
            val bodyEnd = minOf(end, body + len)
            val ctName = when (ct) { 20 -> "Change Cipher Spec"; 21 -> "Alert"; 22 -> "Handshake"; else -> "Application Data" }
            val rn = d.node(top, "TLS record: $ctName", p, minOf(len + 5, end - p)) { "${tlsVersion(ver)}, $len bytes" + if (body + len > end) " (continues in next segment)" else "" }
            when (ct) {
                22 -> if (bodyEnd - body >= 4) {
                    val hs = b.u8(body)
                    when (hs) {
                        1 -> infos += clientHello(d, rn, body, bodyEnd)
                        2 -> { val (i, v) = serverHello(d, rn, body, bodyEnd); infos += i; label = v }
                        11 -> { infos += "Certificate"; d.node(rn, "Certificate", body, bodyEnd - body) { "${b.u32(body) and 0xFFFFFF} bytes" } }
                        12 -> infos += "Server Key Exchange"
                        14 -> infos += "Server Hello Done"
                        16 -> infos += "Client Key Exchange"
                        4 -> infos += "New Session Ticket"
                        else -> infos += if (len > 0 && d.payloadLength > 0 && hs > 24) "Encrypted Handshake Message" else "Handshake type $hs"
                    }
                }
                21 -> {
                    if (len == 2 && bodyEnd - body >= 2) {
                        val level = if (b.u8(body) == 2) "Fatal" else "Warning"
                        val desc = ALERTS[b.u8(body + 1)] ?: "code ${b.u8(body + 1)}"
                        infos += "Alert ($level, $desc)"
                        d.node(rn, "Alert", body, 2) { "$level: $desc" }
                        if (level == "Fatal") d.problem = "TLS fatal alert: $desc"
                    } else infos += "Encrypted Alert"
                }
                20 -> infos += "Change Cipher Spec"
                else -> infos += "Application Data"
            }
            p = body + len
        }
        d.layer(label)
        d.info = infos.distinct().joinToString(", ").ifEmpty { "Continuation data" }
        if (infos.isEmpty()) d.protocol = "TLS"
    }

    private fun clientHello(d: Dissection, parent: Field?, o: Int, end: Int): String {
        val b = d.data
        val n = d.node(parent, "Client Hello", o, end - o)
        var p = o + 4
        d.node(n, "Version", p, 2) { tlsVersion(b.u16(p)) }
        p += 2 + 32
        val sidLen = b.u8(p); p += 1 + sidLen
        val csLen = b.u16(p)
        d.node(n, "Cipher suites", p, csLen + 2) { "${csLen / 2} suites" }
        p += 2 + csLen
        val compLen = b.u8(p); p += 1 + compLen
        if (p + 2 > end) return "Client Hello"
        val extEnd = minOf(end, p + 2 + b.u16(p)); p += 2
        val en = d.node(n, "Extensions", p, extEnd - p)
        val alpn = mutableListOf<String>()
        var versions = ""
        while (p + 4 <= extEnd) {
            val type = b.u16(p); val len = b.u16(p + 2); val v = p + 4
            when (type) {
                0 -> if (len >= 5) {
                    val nl = b.u16(v + 3)
                    d.sni = String(b, v + 5, minOf(nl, extEnd - v - 5), Charsets.US_ASCII)
                    d.node(en, "Server Name Indication", p, len + 4) { d.sni!! }
                }
                16 -> {
                    var q = v + 2
                    while (q < v + len) { val l = b.u8(q); alpn += String(b, q + 1, l, Charsets.US_ASCII); q += l + 1 }
                    d.node(en, "ALPN", p, len + 4) { alpn.joinToString() }
                }
                43 -> {
                    versions = (0 until b.u8(v) / 2).map { tlsVersion(b.u16(v + 1 + it * 2)) }.filter { !it.startsWith("0x") }.joinToString()
                    d.node(en, "Supported versions", p, len + 4) { versions }
                }
                10 -> d.node(en, "Supported groups", p, len + 4) { "${(len - 2) / 2} groups" }
                13 -> d.node(en, "Signature algorithms", p, len + 4) { "${(len - 2) / 2} algorithms" }
                51 -> d.node(en, "Key share", p, len + 4) { "$len bytes" }
                65037 -> d.node(en, "Encrypted Client Hello", p, len + 4) { "real server name is hidden" }
                else -> d.node(en, "Extension $type", p, len + 4) { "$len bytes" }
            }
            p = v + len
        }
        if (d.sni != null && d.dst != null) d.names += d.dst!! to d.sni!!
        return "Client Hello" + (d.sni?.let { " (SNI=$it)" } ?: "") + if (alpn.isNotEmpty()) " [${alpn.joinToString()}]" else ""
    }

    private fun serverHello(d: Dissection, parent: Field?, o: Int, end: Int): Pair<String, String> {
        val b = d.data
        val n = d.node(parent, "Server Hello", o, end - o)
        var p = o + 4
        var version = b.u16(p)
        p += 2 + 32
        val sidLen = b.u8(p); p += 1 + sidLen
        val cipher = b.u16(p)
        d.node(n, "Cipher suite", p, 2) { CIPHERS[cipher] ?: "0x%04x".format(cipher) }
        p += 3
        if (p + 2 <= end) {
            val extEnd = minOf(end, p + 2 + b.u16(p)); p += 2
            while (p + 4 <= extEnd) {
                val type = b.u16(p); val len = b.u16(p + 2)
                if (type == 43 && len == 2) version = b.u16(p + 4)
                p += 4 + len
            }
        }
        d.node(n, "Negotiated version", o + 4, 2) { tlsVersion(version) }
        val label = when (version) { 0x0304 -> "TLSv1.3"; 0x0303 -> "TLSv1.2"; 0x0302 -> "TLSv1.1"; 0x0301 -> "TLSv1.0"; else -> "TLS" }
        if (version < 0x0303) d.problem = "Outdated ${tlsVersion(version)} negotiated"
        return "Server Hello (${tlsVersion(version)}, ${CIPHERS[cipher] ?: "0x%04x".format(cipher)})" to label
    }
}
