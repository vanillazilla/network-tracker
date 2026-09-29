package com.networktracker.capture

/**
 * Display filter. Terms are ANDed; the word `or` separates alternative groups.
 *
 *   google                 free text: matches address, host name, protocol, app or info
 *   proto:dns|mdns         protocol (any layer)          ip:192.168.1.50   either address
 *   src:… dst:…            source / destination          host:youtube  host name or address
 *   port:443 sport: dport: ports                         app:chrome    process name
 *   dir:in|out|broadcast   direction                     mac:aa:bb     MAC address
 *   len>1000 len<100       frame length                  flags:syn|rst TCP flags
 *   problems               only packets flagged as a problem
 *   -term or !term         negates a term
 */
class PacketFilter private constructor(private val groups: List<List<Term>>, val text: String) {

    private class Term(val negate: Boolean, val test: (Packet, TrafficStore) -> Boolean)

    fun matches(p: Packet, s: TrafficStore): Boolean =
        groups.isEmpty() || groups.any { g -> g.all { t -> t.test(p, s) != t.negate } }

    /** Filter for connection-table rows (subset of keys that make sense there). */
    fun matchesText(fields: Map<String, String>): Boolean {
        if (groups.isEmpty()) return true
        return rawGroups.any { g -> g.all { (neg, key, value) -> matchField(fields, key, value) != neg } }
    }

    private var rawGroups: List<List<Triple<Boolean, String?, String>>> = emptyList()

    val isEmpty get() = groups.isEmpty()

    companion object {
        val EMPTY = PacketFilter(emptyList(), "")

        val KEYS = listOf("proto", "protocol", "ip", "addr", "src", "dst", "host", "name", "port", "sport", "dport", "app",
            "process", "dir", "mac", "len", "flags", "problems", "problem", "conv", "state")

        private fun tokenize(s: String): List<String> {
            val out = mutableListOf<String>(); val sb = StringBuilder(); var quoted = false
            for (c in s) {
                when {
                    c == '"' -> quoted = !quoted
                    c.isWhitespace() && !quoted -> { if (sb.isNotEmpty()) out += sb.toString(); sb.clear() }
                    else -> sb.append(c)
                }
            }
            if (sb.isNotEmpty()) out += sb.toString()
            return out
        }

        /** @throws IllegalArgumentException with a user-readable message */
        fun parse(text: String): PacketFilter {
            val tokens = tokenize(text.trim())
            if (tokens.isEmpty()) return EMPTY
            val groups = mutableListOf<MutableList<Term>>(mutableListOf())
            val raw = mutableListOf<MutableList<Triple<Boolean, String?, String>>>(mutableListOf())
            for (tok0 in tokens) {
                if (tok0.equals("or", true) || tok0 == "||") { groups += mutableListOf<Term>(); raw += mutableListOf<Triple<Boolean, String?, String>>(); continue }
                if (tok0.equals("and", true) || tok0 == "&&") continue
                var tok = tok0
                val neg = tok.startsWith("-") || tok.startsWith("!")
                if (neg) tok = tok.substring(1)
                val m = Regex("""^([a-zA-Z]+)\s*(:|=|==|>=|<=|>|<)\s*(.*)$""").find(tok)
                val term: Term
                if (m != null && m.groupValues[1].lowercase() in KEYS) {
                    val key = m.groupValues[1].lowercase()
                    val op = m.groupValues[2]
                    val value = m.groupValues[3].trim('"')
                    if (value.isEmpty()) throw IllegalArgumentException("\"$key\" needs a value, e.g. $key:${example(key)}")
                    term = Term(neg, build(key, op, value))
                    raw.last() += Triple(neg, key, value)
                } else if (m != null && m.groupValues[2] == ":" && m.groupValues[1].lowercase() !in KEYS && !tok.contains("::") && tok.count { it == ':' } == 1) {
                    throw IllegalArgumentException("Unknown filter \"${m.groupValues[1]}\". Try: proto, host, ip, port, app, dir, len, flags, problems")
                } else if (tok.lowercase() in setOf("problems", "problem", "issues", "errors")) {
                    term = Term(neg) { p, _ -> p.problem != null }
                    raw.last() += Triple(neg, "problems", "")
                } else {
                    val needle = tok.lowercase()
                    term = Term(neg) { p, s -> freeText(p, s, needle) }
                    raw.last() += Triple(neg, null, needle)
                }
                groups.last() += term
            }
            return PacketFilter(groups.filter { it.isNotEmpty() }, text).also { f -> f.rawGroups = raw.filter { it.isNotEmpty() } }
        }

        private fun example(key: String) = when (key) {
            "proto", "protocol" -> "dns"; "port", "sport", "dport" -> "443"; "app", "process" -> "chrome"; "dir" -> "out"
            "len" -> ">1000"; "flags" -> "syn"; else -> "192.168.1.1"
        }

        private fun alts(v: String) = v.lowercase().split('|', ',').filter { it.isNotEmpty() }

        private fun build(key: String, op: String, value: String): (Packet, TrafficStore) -> Boolean {
            val vs = alts(value)
            return when (key) {
                "proto", "protocol" -> { p, _ -> vs.any { v -> p.path.lowercase().split('/').any { it == v || it.startsWith(v) } || p.protocol.lowercase().startsWith(v) } }
                "ip", "addr" -> { p, _ -> vs.any { v -> p.src.lowercase().startsWith(v) || p.dst.lowercase().startsWith(v) } }
                "src" -> { p, s -> vs.any { v -> p.src.lowercase().startsWith(v) || s.nameOf(p.src)?.lowercase()?.contains(v) == true } }
                "dst" -> { p, s -> vs.any { v -> p.dst.lowercase().startsWith(v) || s.nameOf(p.dst)?.lowercase()?.contains(v) == true } }
                "host", "name" -> { p, s ->
                    vs.any { v -> p.src.contains(v) || p.dst.contains(v) ||
                        s.nameOf(p.src)?.lowercase()?.contains(v) == true || s.nameOf(p.dst)?.lowercase()?.contains(v) == true }
                }
                "port" -> { p, _ -> vs.any { v -> v.toIntOrNull().let { it == p.srcPort || it == p.dstPort } } }
                "sport" -> { p, _ -> vs.any { v -> v.toIntOrNull() == p.srcPort } }
                "dport" -> { p, _ -> vs.any { v -> v.toIntOrNull() == p.dstPort } }
                "app", "process" -> { p, s -> vs.any { v -> s.appOf(p)?.lowercase()?.contains(v) == true } }
                "dir" -> { p, _ -> vs.any { v -> p.direction.name.lowercase().startsWith(v) || (v == "local" && p.direction == Direction.BROADCAST) } }
                "mac" -> { p, _ -> vs.any { v -> p.srcMac?.startsWith(v) == true || p.dstMac?.startsWith(v) == true } }
                "len" -> {
                    val n = value.trimStart('>', '<', '=').toIntOrNull() ?: throw IllegalArgumentException("len needs a number, e.g. len>1000")
                    val realOp = if (op == ":" || op == "=") value.takeWhile { it in "<>=" }.ifEmpty { "==" } else op
                    { p, _ -> when (realOp) { ">" -> p.length > n; "<" -> p.length < n; ">=" -> p.length >= n; "<=" -> p.length <= n; else -> p.length == n } }
                }
                "flags" -> { p, _ ->
                    p.transport == "TCP" && vs.all { v -> Dissector.flagNames(p.tcpFlags).lowercase().contains(v) }
                }
                "problems", "problem" -> { p, _ -> p.problem != null && (value == "true" || vs.any { p.problem!!.lowercase().contains(it) }) }
                "conv" -> { p, _ -> vs.any { v -> v.toIntOrNull() == p.conv?.id } }
                "state" -> { _, _ -> true }
                else -> { _, _ -> true }
            }
        }

        private fun freeText(p: Packet, s: TrafficStore, needle: String): Boolean =
            p.src.contains(needle) || p.dst.contains(needle) ||
                p.protocol.lowercase().contains(needle) || p.info.lowercase().contains(needle) ||
                s.nameOf(p.src)?.lowercase()?.contains(needle) == true || s.nameOf(p.dst)?.lowercase()?.contains(needle) == true ||
                s.appOf(p)?.lowercase()?.contains(needle) == true ||
                (p.srcPort >= 0 && p.srcPort.toString() == needle) || (p.dstPort >= 0 && p.dstPort.toString() == needle)

        /** Generic matcher for tables that aren't packets (connections, conversations). */
        private fun matchField(fields: Map<String, String>, key: String?, value: String): Boolean {
            val vs = alts(value)
            if (key == null) return fields.values.any { it.lowercase().contains(value) }
            val k = when (key) {
                "protocol" -> "proto"; "addr" -> "ip"; "name" -> "host"; "process" -> "app"; "problem" -> "problems"; else -> key
            }
            if (k == "problems") return fields["problems"]?.let { it != "0" && it.isNotEmpty() } == true
            if (k == "ip") return vs.any { v -> (fields["src"] ?: "").startsWith(v) || (fields["dst"] ?: "").startsWith(v) }
            if (k == "host") return vs.any { v -> listOf("src", "dst", "host").any { (fields[it] ?: "").lowercase().contains(v) } }
            if (k == "port") return vs.any { v -> fields["sport"] == v || fields["dport"] == v }
            val f = fields[k] ?: return true
            return vs.any { f.lowercase().contains(it) }
        }
    }
}
