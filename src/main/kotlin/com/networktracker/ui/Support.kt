package com.networktracker.ui

import com.networktracker.monitor.Diagnoser
import com.networktracker.monitor.MonitorEngine
import com.networktracker.monitor.Severity
import com.networktracker.monitor.TargetRole
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.prefs.Preferences

object Settings {
    private val prefs: Preferences = Preferences.userRoot().node("com/networktracker/app")

    var dark: Boolean
        get() = prefs.getBoolean("dark", true)
        set(v) = prefs.putBoolean("dark", v)
    var intervalIndex: Int
        get() = prefs.getInt("interval", 1)
        set(v) = prefs.putInt("interval", v)
    var timeoutIndex: Int
        get() = prefs.getInt("timeout", 1)
        set(v) = prefs.putInt("timeout", v)
    var windowIndex: Int
        get() = prefs.getInt("window", 1)
        set(v) = prefs.putInt("window", v)
    var bounds: String?
        get() = prefs.get("bounds", null)
        set(v) = if (v == null) prefs.remove("bounds") else prefs.put("bounds", v)

    /** User-added targets as host names. */
    var customTargets: List<String>
        get() = prefs.get("targets", "").split('\n').map { it.trim() }.filter { it.isNotEmpty() }
        set(v) = prefs.put("targets", v.joinToString("\n"))
}

object Exporter {
    private val iso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
    private val human = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")

    fun writeCsv(engine: MonitorEngine, file: File) {
        file.bufferedWriter().use { w ->
            w.write("timestamp,round,role,name,host,address,rtt_ms,lost\n")
            val rows = engine.targets.flatMap { t -> t.samples.map { t to it } }.sortedWith(compareBy({ it.second.tick }, { it.first.role.order }))
            for ((t, s) in rows) {
                w.write(listOf(
                    iso.format(Date(s.time)), s.tick.toString(), t.role.label, csv(t.name), csv(t.host), t.displayAddress,
                    if (s.lost) "" else "%.2f".format(java.util.Locale.ROOT, s.rtt), if (s.lost) "1" else "0",
                ).joinToString(","))
                w.write("\n")
            }
        }
    }

    private fun csv(s: String) = if (s.any { it == ',' || it == '"' }) "\"" + s.replace("\"", "\"\"") + "\"" else s

    fun report(engine: MonitorEngine, fromTime: Long, windowLabel: String): String = buildString {
        val d = Diagnoser.diagnose(engine.targets, fromTime, engine.wifi, engine.adapter)
        val line = "=".repeat(72)
        appendLine(line)
        appendLine("NETWORK TRACKER — DIAGNOSTIC REPORT")
        appendLine("Generated: ${human.format(Date())}")
        if (engine.startedAt > 0) appendLine("Monitoring since: ${human.format(Date(engine.startedAt))}")
        appendLine("Analysis window: $windowLabel   Probe interval: ${engine.intervalMs} ms   Timeout: ${engine.timeoutMs} ms")
        appendLine(line)
        appendLine()
        appendLine("VERDICT: ${d.headline}  [${d.health}]")
        appendLine(wrap(d.explanation))
        if (d.recommendations.isNotEmpty()) {
            appendLine()
            appendLine("Recommended actions:")
            d.recommendations.forEachIndexed { i, r -> appendLine(wrap("${i + 1}. $r", "   ")) }
        }
        appendLine()
        appendLine("CONNECTION")
        engine.adapter?.let {
            appendLine("  Adapter:        ${it.displayName} (${if (it.isWireless || engine.wifi != null) "Wi-Fi" else "wired"})")
            appendLine("  Local address:  ${it.localAddress}${it.prefixLength?.let { p -> "/$p" } ?: ""}")
        }
        appendLine("  Gateway:        ${engine.gateway ?: "none"}")
        appendLine("  ISP edge:       ${engine.ispHop ?: "not detected"}")
        appendLine("  DNS servers:    ${engine.dnsServers.joinToString().ifEmpty { "none" }}")
        engine.wifi?.let { w ->
            appendLine("  Wi-Fi:          ${w.ssid}  signal ${w.signalPercent}% (~${w.approxDbm} dBm)  ${w.band ?: ""} ch ${w.channel ?: "?"}  ${w.radioType ?: ""}")
            val hist = engine.wifiHistory.filter { it.time >= fromTime }
            if (hist.isNotEmpty()) appendLine("  Wi-Fi signal:   min ${hist.minOf { it.signal }}%  max ${hist.maxOf { it.signal }}%  roams ${hist.zipWithNext().count { (a, b) -> a.bssid != b.bssid }}")
        }
        appendLine()
        appendLine("PER-TARGET STATISTICS")
        appendLine(String.format("  %-9s %-26s %-16s %6s %6s %7s %8s %8s %8s %8s", "Role", "Name", "Address", "Sent", "Lost", "Loss", "Min", "Avg", "Max", "Jitter"))
        for (t in engine.targets) {
            val s = t.summary(fromTime)
            appendLine(String.format("  %-9s %-26s %-16s %6d %6d %7s %8s %8s %8s %8s",
                t.role.label, t.name.take(26), t.displayAddress.take(16), s.sent, s.lost, Diagnoser.pct(s.lossPercent),
                Diagnoser.ms(s.min), Diagnoser.ms(s.avg), Diagnoser.ms(s.max), Diagnoser.ms(s.jitter)))
        }
        appendLine()
        appendLine("MEASUREMENTS")
        d.findings.forEach { appendLine(wrap("[${it.health}] ${it.text}", "   ")) }
        appendLine()
        appendLine("NOTABLE EVENTS (warnings and errors)")
        val ev = engine.events.filter { it.time >= fromTime && (it.severity == Severity.ERROR || it.severity == Severity.WARNING || it.severity == Severity.SUCCESS) }
        if (ev.isEmpty()) appendLine("  none")
        ev.takeLast(300).forEach { appendLine("  ${human.format(Date(it.time))}  %-8s %-9s %s".format(it.severity, it.source, it.message)) }
        appendLine()
        appendLine("How to read this: probes to the router, ISP edge, Internet anchors and your targets are sent at the")
        appendLine("same moment each round. Loss that also appears at the router is local (PC <-> router); loss that")
        appendLine("starts at the ISP edge or Internet anchors while the router is fine is beyond your home network.")
        if (engine.targets.none { it.role == TargetRole.GATEWAY }) appendLine("NOTE: no router target was monitored.")
    }

    private fun wrap(text: String, indent: String = "", width: Int = 96): String {
        val words = text.split(' ')
        val sb = StringBuilder("  "); var lineLen = 2
        var lineStart = true
        for (w in words) {
            if (lineLen + w.length + 1 > width && !lineStart) {
                sb.append('\n').append("  ").append(indent); lineLen = 2 + indent.length; lineStart = true
            }
            if (!lineStart) { sb.append(' '); lineLen++ }
            sb.append(w); lineLen += w.length
            lineStart = false
        }
        return sb.toString()
    }
}
