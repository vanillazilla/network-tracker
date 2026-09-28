package com.networktracker.monitor

import com.networktracker.net.AdapterInfo
import com.networktracker.net.WifiInfo

data class TierStatus(
    val title: String,
    val subtitle: String,
    val health: Health,
    val primary: String,
    val secondary: String,
)

data class Finding(val health: Health, val text: String)

data class Diagnosis(
    val health: Health,
    val headline: String,
    val explanation: String,
    val findings: List<Finding>,
    val recommendations: List<String>,
    val path: List<TierStatus>,
)

/**
 * Turns raw statistics into a verdict about *where* a problem is. The core idea: each probe round
 * pings the router, the ISP edge, public anchors and your targets at the same moment, so a loss can
 * be attributed to the first point in the path where it appears.
 */
object Diagnoser {
    private const val MIN_SAMPLES = 5

    private data class Limits(
        val lossWarn: Double, val lossBad: Double,
        val latWarn: Double, val latBad: Double,
        val jitWarn: Double, val jitBad: Double,
    )

    private val GATEWAY_LIMITS = Limits(1.0, 3.0, 15.0, 50.0, 8.0, 25.0)
    // ISP routers often rate-limit ping replies, so allow more loss before calling it a problem.
    private val ISP_LIMITS = Limits(3.0, 10.0, 50.0, 120.0, 20.0, 50.0)
    private val INTERNET_LIMITS = Limits(1.0, 3.0, 90.0, 180.0, 20.0, 50.0)
    private val DNS_LIMITS = Limits(2.0, 10.0, 120.0, 400.0, 80.0, 200.0)
    private val REMOTE_LIMITS = Limits(1.0, 3.0, 150.0, 300.0, 30.0, 70.0)

    private fun rate(s: Summary, l: Limits, lossOverride: Double? = null): Health {
        if (s.sent < MIN_SAMPLES) return Health.UNKNOWN
        if (s.received == 0) return Health.BAD
        val loss = lossOverride ?: s.lossPercent
        return when {
            loss >= l.lossBad || s.avg >= l.latBad || s.jitter >= l.jitBad -> Health.BAD
            loss >= l.lossWarn || s.avg >= l.latWarn || s.jitter >= l.jitWarn -> Health.WARN
            else -> Health.GOOD
        }
    }

    private fun worst(vararg h: Health): Health = when {
        Health.BAD in h -> Health.BAD
        Health.WARN in h -> Health.WARN
        Health.GOOD in h -> Health.GOOD
        else -> Health.UNKNOWN
    }

    /** Rounds where the target was far slower than its own median. */
    private fun spikeTicks(t: Target, fromTime: Long, local: Boolean): Set<Long> {
        val start = t.indexFrom(fromTime)
        val rtts = (start until t.samples.size).map { t.samples[it].rtt }.filter { !it.isNaN() }.sorted()
        if (rtts.size < 10) return emptySet()
        val median = rtts[rtts.size / 2].toDouble()
        val threshold = if (local) median + 20 else maxOf(median * 2.5, median + 40)
        return (start until t.samples.size).map { t.samples[it] }
            .filter { !it.lost && it.rtt > threshold }.map { it.tick }.toSet()
    }

    fun wifiHealth(wifi: WifiInfo?): Health {
        val s = wifi?.signalPercent ?: return Health.UNKNOWN
        return when { s < 40 -> Health.BAD; s < 60 -> Health.WARN; else -> Health.GOOD }
    }

    fun ms(v: Double) = if (v.isNaN()) "—" else if (v < 10) "%.1f ms".format(v) else "%.0f ms".format(v)
    fun pct(v: Double) = if (v.isNaN()) "—" else "%.1f%%".format(v)
    private fun statLine(s: Summary) =
        if (s.sent == 0) "no data" else "${pct(s.lossPercent)} loss · avg ${ms(s.avg)} · jitter ${ms(s.jitter)}"

    fun diagnose(
        targets: List<Target>,
        fromTime: Long,
        wifi: WifiInfo?,
        adapter: AdapterInfo?,
    ): Diagnosis {
        val gw = targets.firstOrNull { it.role == TargetRole.GATEWAY }
        val isp = targets.firstOrNull { it.role == TargetRole.ISP }
        val anchors = targets.filter { it.role == TargetRole.INTERNET }
        val dns = targets.filter { it.role == TargetRole.DNS }
        val remotes = targets.filter { it.role == TargetRole.CUSTOM }

        val gwS = gw?.summary(fromTime) ?: Summary.EMPTY
        val ispS = isp?.summary(fromTime) ?: Summary.EMPTY
        val anchorS = anchors.map { it.summary(fromTime) }
        val dnsS = dns.map { it.summary(fromTime) }
        val remoteS = remotes.map { it.summary(fromTime) }

        // "Internet loss" = rounds where *every* anchor was lost. One anchor alone dropping a
        // ping is that anchor's problem; all of them at once means your connection dropped it.
        val anchorTicks = anchors.map { it.ticks(fromTime) }.reduceOrNull { a, b -> a intersect b } ?: emptySet()
        val inetLost = anchors.map { it.lostTicks(fromTime) }.reduceOrNull { a, b -> a intersect b } ?: emptySet()
        val inetLossPct = if (anchorTicks.isEmpty()) 0.0 else inetLost.size * 100.0 / anchorTicks.size
        val bestAnchor = anchorS.filter { it.received > 0 }.minByOrNull { it.avg }
        val inetSummary = bestAnchor ?: anchorS.firstOrNull() ?: Summary.EMPTY
        val gwLost = gw?.lostTicks(fromTime) ?: emptySet()

        // Many routers answer pings from a low-priority CPU path. If the router looks *slower*
        // than the Internet behind it, its ping latency isn't meaningful—only its loss is.
        val routerDeprioritizes = gwS.received > 0 && inetSummary.received > 0 && gwS.avg > inetSummary.avg
        val gwH = if (routerDeprioritizes) rate(gwS.copy(avg = 0.0, jitter = 0.0), GATEWAY_LIMITS) else rate(gwS, GATEWAY_LIMITS)
        // An ISP router that never answers while the Internet behind it works is just ignoring ping.
        val ispSilent = ispS.sent >= MIN_SAMPLES && ispS.received == 0 && anchorS.any { it.received > 0 }
        val ispH = if (ispSilent) Health.UNKNOWN else rate(ispS, ISP_LIMITS)
        val inetH = if (anchors.isEmpty()) Health.UNKNOWN else rate(inetSummary.copy(sent = anchorTicks.size), INTERNET_LIMITS, inetLossPct)
        val dnsH = worst(*dnsS.map { rate(it, DNS_LIMITS) }.toTypedArray())
        val remoteHs = remoteS.map { rate(it, REMOTE_LIMITS) }
        val remoteH = worst(*remoteHs.toTypedArray())
        val linkH = when {
            adapter == null && gwS.sent == 0 -> Health.UNKNOWN
            adapter?.isWireless == true || wifi != null -> wifiHealth(wifi)
            else -> Health.GOOD
        }

        // ---- Path overview ----
        val path = buildList {
            add(TierStatus(
                "This PC",
                adapter?.let { if (it.isWireless || wifi != null) "Wi-Fi · ${wifi?.ssid ?: it.displayName}" else "Wired · ${it.localAddress}" } ?: "No adapter",
                linkH,
                wifi?.signalPercent?.let { "Signal $it%" } ?: (adapter?.localAddress ?: "—"),
                wifi?.let { w -> listOfNotNull(w.band ?: w.radioType, w.receiveMbps?.let { "${it.toInt()} Mbps" }).joinToString(" · ") }
                    ?: (adapter?.displayName ?: ""),
            ))
            add(TierStatus("Router", gw?.displayAddress ?: "not detected", gwH,
                if (gwS.sent == 0) "—" else "${pct(gwS.lossPercent)} loss", "avg ${ms(gwS.avg)}"))
            add(TierStatus("ISP Edge", isp?.displayAddress ?: "not detected", ispH,
                if (ispS.sent == 0) "—" else if (ispSilent) "No ping reply" else "${pct(ispS.lossPercent)} loss",
                if (ispSilent) "" else "avg ${ms(ispS.avg)}"))
            add(TierStatus("Internet", anchors.joinToString(", ") { it.displayAddress }.ifEmpty { "none" }, inetH,
                if (anchorTicks.isEmpty()) "—" else "${pct(inetLossPct)} loss", "avg ${ms(inetSummary.avg)}"))
            if (dns.isNotEmpty()) add(TierStatus("DNS", dns.first().displayAddress, dnsH,
                dnsS.first().let { if (it.sent == 0) "—" else "${pct(it.lossPercent)} fail" }, "avg ${ms(dnsS.first().avg)}"))
            add(TierStatus("Your Targets",
                if (remotes.isEmpty()) "none added" else "${remotes.size} host${if (remotes.size > 1) "s" else ""}",
                remoteH,
                if (remoteS.isEmpty() || remoteS.all { it.sent == 0 }) "—" else "${pct(remoteS.maxOf { it.lossPercent })} loss",
                if (remoteS.isEmpty()) "" else "worst avg ${ms(remoteS.filter { it.received > 0 }.maxOfOrNull { it.avg } ?: Double.NaN)}"))
        }

        // ---- Findings ----
        val findings = mutableListOf<Finding>()
        if (wifi != null) findings += Finding(linkH,
            "Wi-Fi \"${wifi.ssid}\": signal ${wifi.signalPercent}% (≈ ${wifi.approxDbm} dBm)" +
                (wifi.band?.let { ", $it" } ?: "") + (wifi.receiveMbps?.let { ", link ${it.toInt()} Mbps" } ?: ""))
        else if (adapter != null) findings += Finding(Health.GOOD, "Wired connection via ${adapter.displayName}")
        gw?.let { findings += Finding(gwH, "Router ${it.displayAddress}: ${statLine(gwS)}") }
        if (routerDeprioritizes && gwS.avg > 5)
            findings += Finding(Health.GOOD, "Router answers pings slower than Internet hosts do. This is normal: it replies to ping at low priority, so its latency is ignored.")
        isp?.let {
            findings += if (ispSilent) Finding(Health.UNKNOWN, "ISP edge ${it.displayAddress} does not answer ping (but traffic passes through it fine), so it is ignored. Try \"Re-detect network\".")
            else Finding(ispH, "ISP edge ${it.displayAddress}: ${statLine(ispS)}")
        }
        if (anchors.isNotEmpty()) findings += Finding(inetH,
            "Internet (all anchors lost at once): ${pct(inetLossPct)} loss · best avg ${ms(inetSummary.avg)} · jitter ${ms(inetSummary.jitter)}")
        dns.forEachIndexed { i, t -> findings += Finding(rate(dnsS[i], DNS_LIMITS),
            "DNS server ${t.displayAddress}: ${pct(dnsS[i].lossPercent)} failed · avg ${ms(dnsS[i].avg)}") }
        remotes.forEachIndexed { i, t -> findings += Finding(remoteHs[i], "${t.name} (${t.displayAddress}): ${statLine(remoteS[i])}") }

        // Loss attribution: of the rounds the Internet was lost, how many were already lost at the router?
        if (gw != null && inetLost.size >= 2) {
            val local = inetLost.count { it in gwLost }
            val p = local * 100.0 / inetLost.size
            findings += Finding(if (p >= 50) Health.BAD else Health.WARN,
                "Of ${inetLost.size} rounds where the Internet was unreachable, $local (${"%.0f".format(p)}%) were also lost " +
                    "at the router → ${if (p >= 50) "mostly a local (PC ↔ router) problem" else "mostly beyond your router"}.")
        }
        // Same idea for latency spikes: were the slow Internet rounds already slow at the router?
        if (gw != null && anchors.isNotEmpty()) {
            val inetSpikes = anchors.map { spikeTicks(it, fromTime, local = false) }.reduce { a, b -> a intersect b }
            if (inetSpikes.size >= 3) {
                val gwSpikes = spikeTicks(gw, fromTime, local = true)
                val local = inetSpikes.count { it in gwSpikes }
                val p = local * 100.0 / inetSpikes.size
                findings += Finding(Health.WARN,
                    "${inetSpikes.size} Internet latency spikes; $local (${"%.0f".format(p)}%) were also slow at the router → " +
                        if (p >= 50) "caused locally (typically Wi-Fi interference or a busy router)." else "mostly caused beyond your router.")
            }
        }
        val ispLost = isp?.lostTicks(fromTime) ?: emptySet()
        if (isp != null && ispLost.isNotEmpty() && inetLost.isNotEmpty()) {
            val carried = ispLost.count { it in inetLost }
            if (ispLost.size >= 3 && carried * 3 < ispLost.size)
                findings += Finding(Health.GOOD, "Most loss at the ISP edge does not carry through to the Internet, so it is ICMP rate-limiting, not real loss.")
        }
        remotes.forEachIndexed { i, t ->
            val lost = t.lostTicks(fromTime)
            if (lost.size >= 2) {
                val own = lost.count { it !in inetLost && it !in gwLost }
                if (own * 2 >= lost.size) findings += Finding(Health.WARN,
                    "${own} of ${lost.size} losses to ${t.name} happened while the router and Internet were fine → the problem is on the path to that host or the host itself.")
            }
        }

        // ---- Verdict ----
        val hasData = targets.any { it.samples.isNotEmpty() }
        val onWifi = wifi != null || adapter?.isWireless == true
        val wifiAdvice = listOf(
            "Move closer to the router or remove obstructions; signal below ~60% often causes drops.",
            "If available, use the 5 GHz band (or 6 GHz), which is less crowded than 2.4 GHz.",
            "Try a different Wi-Fi channel in the router settings to avoid neighbours' interference.",
            "Update the Wi-Fi adapter driver and disable its power-saving mode.",
            "Test with an Ethernet cable: if the problem disappears, the Wi-Fi link is the cause.",
        )
        val wiredAdvice = listOf(
            "Reseat or replace the Ethernet cable and try a different port on the router.",
            "Restart the router. If loss persists on a known-good cable, the router may be failing.",
            "Check the adapter's link speed/duplex in Network Info (should be 1 Gbps full duplex on most setups).",
        )

        val d: Triple<Health, String, String>
        val recs = mutableListOf<String>()
        when {
            !hasData -> {
                d = Triple(Health.UNKNOWN, "Waiting for data", "Press Start to begin monitoring. A diagnosis appears after a few seconds of data; longer runs give more reliable results.")
            }
            gw != null && gwS.sent >= MIN_SAMPLES && gwS.received == 0 -> {
                d = Triple(Health.BAD, "Your router is unreachable",
                    "This computer gets no replies from your router (${gw.displayAddress}), so nothing beyond it can work. The problem is this computer's connection to the router, or the router itself.")
                recs += if (onWifi) listOf("Check that Wi-Fi is connected to the right network.") + wifiAdvice.take(2)
                else listOf("Check the Ethernet cable and link lights on the router and PC.")
                recs += "Restart the router. If other devices also can't connect, the router is at fault."
            }
            gwH == Health.BAD -> {
                d = Triple(Health.BAD, "Problem between this computer and your router",
                    "Packets are already being lost or delayed on the first hop, to your router. Every connection you make crosses this link, so this is the likely cause of your issues." +
                        if (onWifi) " You are on Wi-Fi${wifi?.signalPercent?.let { " with $it% signal" } ?: ""}, which is the most common culprit." else "")
                recs += if (onWifi) wifiAdvice else wiredAdvice
                recs += "If several devices show the same symptoms, the router itself may be overloaded or faulty: restart it or update its firmware."
            }
            inetH == Health.BAD || (inetH == Health.WARN && gwH != Health.WARN) -> {
                val lossy = inetLossPct >= INTERNET_LIMITS.lossWarn
                if (ispH == Health.BAD || ispH == Health.WARN) {
                    d = Triple(inetH, "Problem between your router and your ISP",
                        "Your router responds fine, but ${if (lossy) "loss" else "latency"} begins at your ISP's first router and carries on to the Internet. The cause is your modem, the line (cable/DSL/fibre) to your ISP, or the ISP's local equipment.")
                    recs += "Restart your modem and router (unplug for 30 seconds)."
                    recs += "Check the coax/DSL/fibre cabling and splitters between the wall and the modem."
                    recs += "Check your ISP's outage page, then contact them with the exported report as evidence."
                } else if (!lossy && gwH != Health.BAD) {
                    d = Triple(inetH, "High latency beyond your router",
                        "Your local network is fine, but latency to the Internet is ${ms(inetSummary.avg)} with ${ms(inetSummary.jitter)} jitter. This is often caused by the connection being saturated (downloads, streaming, backups) — \"bufferbloat\" — or by ISP congestion.")
                    recs += "Pause large uploads/downloads on your network and see if latency drops."
                    recs += "Enable SQM / Smart Queue / QoS on the router if it supports it."
                    recs += "If it persists at quiet times, contact your ISP."
                } else {
                    d = Triple(inetH, "Problem beyond your router (ISP or upstream)",
                        "Your router responds reliably, but the Internet anchors (${anchors.joinToString { it.host }}) are dropping at the same moments. The problem lies between your router and the Internet — typically your modem, ISP line or ISP network.")
                    recs += "Restart your modem and router."
                    recs += "Check your ISP's outage status page."
                    recs += "Run a Traceroute to 8.8.8.8 to see which hop the loss starts at, and share the report with your ISP."
                }
            }
            dnsH == Health.BAD || dnsH == Health.WARN -> {
                d = Triple(dnsH, "DNS server is slow or unreliable",
                    "Connectivity is fine, but your DNS server (${dns.joinToString { it.displayAddress }}) is failing or slow to answer. Websites will be slow to start loading or fail with \"server not found\" errors.")
                recs += "Change your DNS servers to 1.1.1.1 and 8.8.8.8 (in the router, or in Windows adapter settings)."
                recs += "If the DNS server is your router, restarting it may help."
            }
            remoteH == Health.BAD || remoteH == Health.WARN -> {
                val bad = remotes.filterIndexed { i, _ -> remoteHs[i] == Health.BAD || remoteHs[i] == Health.WARN }
                d = Triple(remoteH, "Problem reaching ${bad.joinToString { it.name }}",
                    "Your router and the Internet anchors are healthy, but ${bad.joinToString { it.name }} ${if (bad.size > 1) "show" else "shows"} loss or high latency. The problem is at the remote host or on the network path to it, not on your side.")
                recs += "Use the Traceroute tab on that host to find where along the path the problem starts."
                recs += "Some servers deliberately rate-limit or ignore ping; check whether the actual service is affected."
            }
            gwH == Health.WARN -> {
                d = Triple(Health.WARN, "Minor instability on your local link",
                    "Everything works, but the link to your router shows some loss or jitter. It may cause occasional hiccups in calls or games.")
                recs += if (onWifi) wifiAdvice.take(3) else wiredAdvice.take(2)
            }
            listOf(gwH, ispH, inetH, dnsH, remoteH).all { it == Health.UNKNOWN } -> {
                d = Triple(Health.UNKNOWN, "Collecting data…", "A diagnosis appears after a few rounds of probes.")
            }
            else -> {
                d = Triple(Health.GOOD, "Your connection looks healthy",
                    "No significant packet loss, latency or jitter was detected on any part of the path. Keep monitoring running while the problem happens to capture evidence.")
            }
        }
        if (onWifi && linkH == Health.BAD && d.first != Health.BAD && recs.none { it in wifiAdvice })
            recs += wifiAdvice.first()

        return Diagnosis(d.first, d.second, d.third, findings, recs, path)
    }
}
