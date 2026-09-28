package com.networktracker.monitor

import com.networktracker.net.AdapterInfo
import com.networktracker.net.DnsProbe
import com.networktracker.net.NetInfo
import com.networktracker.net.PingStatus
import com.networktracker.net.Pinger
import com.networktracker.net.TraceSession
import com.networktracker.net.WifiInfo
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext
import java.net.InetAddress

/**
 * Probes every target once per interval, all in parallel, so each round ("tick") is a snapshot of
 * the whole path at one moment. Comparing which targets lost the same tick is what lets us tell a
 * local problem (router also lost) from an upstream one (router fine, Internet lost).
 *
 * All state is owned by the Swing thread; only the probes themselves run on IO threads.
 */
class MonitorEngine {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Swing)
    private val pinger = Pinger.default

    val targets = mutableListOf<Target>()
    val events = mutableListOf<NetEvent>()
    val wifiHistory = mutableListOf<WifiSample>()

    var gateway: String? = null; private set
    var dnsServers: List<String> = emptyList(); private set
    var wifi: WifiInfo? = null; private set
    var adapter: AdapterInfo? = null; private set
    var ispHop: String? = null; private set
    var detecting = false; private set

    var intervalMs = 1000
    var timeoutMs = 1000
    var startedAt = 0L; private set
    val running get() = job?.isActive == true
    private var job: Job? = null
    private var infoJob: Job? = null
    private var tick = 0L
    private var colorCounter = 0

    private val tickListeners = mutableListOf<() -> Unit>()
    private val changeListeners = mutableListOf<() -> Unit>()
    private val eventListeners = mutableListOf<(NetEvent) -> Unit>()

    fun onTick(l: () -> Unit) { tickListeners += l }
    /** Targets added/removed, start/stop, network info refreshed. */
    fun onChange(l: () -> Unit) { changeListeners += l }
    fun onEvent(l: (NetEvent) -> Unit) { eventListeners += l }
    private fun changed() = changeListeners.forEach { it() }

    fun log(severity: Severity, source: String, message: String) {
        val e = NetEvent(System.currentTimeMillis(), severity, source, message)
        events += e
        if (events.size > 20_000) events.subList(0, 5_000).clear()
        eventListeners.forEach { it(e) }
    }

    fun addTarget(target: Target): Target {
        targets.firstOrNull { it.host.equals(target.host, true) && it.kind == target.kind && it.role == target.role }
            ?.let { return it }
        target.colorIndex = colorCounter++
        targets += target
        targets.sortBy { it.role.order }
        scope.launch { resolve(target) }
        changed()
        return target
    }

    fun removeTarget(target: Target) {
        targets.remove(target)
        changed()
    }

    private suspend fun resolve(t: Target): InetAddress? {
        t.address?.let { return it }
        val addr = withContext(Dispatchers.IO) {
            runCatching { InetAddress.getByName(t.host) }
                .onFailure { t.resolveError = "Could not resolve ${t.host}" }
                .getOrNull()
        }
        if (addr != null) { t.address = addr; t.resolveError = null }
        return addr
    }

    /** Detects gateway, DNS, adapter and the ISP's first router, and sets up the standard targets. */
    fun autoDetect(onDone: () -> Unit = {}) {
        if (detecting) return
        detecting = true
        changed()
        scope.launch {
            try {
                refreshInfo()
                gateway?.let { addTarget(Target(TargetRole.GATEWAY, "Router (gateway)", it)) }
                    ?: log(Severity.ERROR, "Network", "No default gateway found. Are you connected to a network?")
                addTarget(Target(TargetRole.INTERNET, "Cloudflare DNS", "1.1.1.1"))
                addTarget(Target(TargetRole.INTERNET, "Google DNS", "8.8.8.8"))
                dnsServers.firstOrNull()?.let {
                    addTarget(Target(TargetRole.DNS, "DNS lookup ($it)", it, ProbeKind.DNS))
                }
                detectIspHop()?.let { addTarget(Target(TargetRole.ISP, "ISP edge router", it)) }
                log(Severity.INFO, "Network", buildString {
                    append("Detected gateway ${gateway ?: "none"}")
                    append(", ISP edge ${ispHop ?: "not found"}")
                    append(", DNS ${dnsServers.joinToString().ifEmpty { "none" }}")
                    adapter?.let { append(", adapter \"${it.displayName}\" (${if (it.isWireless) "Wi-Fi" else "wired"})") }
                })
            } finally {
                detecting = false
                changed()
                onDone()
            }
        }
    }

    /**
     * The ISP edge is the first router beyond your own network: the first responding hop after the
     * gateway that isn't a home-network address (CGNAT counts as the ISP's). Some routers answer
     * traceroute probes but ignore direct pings, so a candidate must also reply to a direct echo.
     */
    private suspend fun detectIspHop(): String? {
        val trace = TraceSession(InetAddress.getByName("8.8.8.8"), pinger)
        trace.discover(maxHops = 10, timeoutMs = 1200)
        val candidates = trace.hops.drop(1).mapNotNull { it.address }
            .filter { it != gateway && it != "8.8.8.8" }
            .distinct()
            .take(4)
        val ordered = candidates.filter { !NetInfo.isPrivate(it, includeCgnat = false) } +
            candidates.filter { NetInfo.isPrivate(it, includeCgnat = false) }
        ispHop = ordered.firstOrNull { answersPing(it) }
        return ispHop
    }

    private suspend fun answersPing(ip: String): Boolean = withContext(Dispatchers.IO) {
        val addr = InetAddress.getByName(ip)
        (1..3).any { pinger.ping(addr, 1000).isReply }
    }

    suspend fun refreshInfo() {
        val (gw, dns, wf) = withContext(Dispatchers.IO) {
            Triple(NetInfo.defaultGateway(), NetInfo.dnsServers(), NetInfo.wifi())
        }
        val ad = withContext(Dispatchers.IO) { NetInfo.primaryAdapter(wf) }
        if (gateway != null && gw != gateway) {
            log(Severity.WARNING, "Network", "Default gateway changed from $gateway to ${gw ?: "none"}")
        }
        gateway = gw; dnsServers = dns; adapter = ad
        updateWifi(wf)
        changed()
    }

    private fun updateWifi(new: WifiInfo?) {
        val old = wifi
        wifi = new
        if (new?.signalPercent != null) {
            wifiHistory += WifiSample(System.currentTimeMillis(), new.signalPercent, new.bssid)
            if (wifiHistory.size > 50_000) wifiHistory.subList(0, 10_000).clear()
        }
        if (!running) return
        when {
            old != null && new == null -> log(Severity.ERROR, "Wi-Fi", "Wi-Fi disconnected")
            old == null && new != null && wifiHistory.size > 1 -> log(Severity.SUCCESS, "Wi-Fi", "Wi-Fi connected to ${new.ssid}")
            old != null && new != null -> {
                if (old.bssid != new.bssid && new.bssid != null)
                    log(Severity.WARNING, "Wi-Fi", "Roamed to access point ${new.bssid} (signal ${new.signalPercent}%). Roaming often causes brief packet loss.")
                val o = old.signalPercent ?: 100; val n = new.signalPercent ?: 100
                if (o >= 40 && n < 40) log(Severity.WARNING, "Wi-Fi", "Wi-Fi signal is weak: $n% (≈ ${new.approxDbm} dBm)")
                if (o < 40 && n >= 50) log(Severity.INFO, "Wi-Fi", "Wi-Fi signal recovered: $n%")
            }
        }
    }

    fun start() {
        if (running) return
        startedAt = System.currentTimeMillis()
        log(Severity.INFO, "Monitor", "Monitoring started (${targets.size} targets, every $intervalMs ms)")
        job = scope.launch {
            while (isActive) {
                val roundStart = System.currentTimeMillis()
                val snapshot = targets.toList()
                val results = coroutineScope {
                    snapshot.map { t -> async { probe(t) } }.awaitAll()
                }
                tick++
                val signals = snapshot.mapIndexedNotNull { i, t ->
                    if (t in targets) record(t, Sample(tick, roundStart, results[i]))?.let { t to it } else null
                }
                logRound(signals)
                tickListeners.forEach { it() }
                val elapsed = System.currentTimeMillis() - roundStart
                delay((intervalMs - elapsed).coerceAtLeast(20))
            }
        }
        infoJob = scope.launch {
            var n = 0
            while (isActive) {
                delay(5000)
                n++
                val wf = withContext(Dispatchers.IO) { NetInfo.wifi() }
                updateWifi(wf)
                if (n % 6 == 0) refreshInfo()
            }
        }
        changed()
    }

    fun stop() {
        if (!running) return
        job?.cancel(); infoJob?.cancel()
        job = null; infoJob = null
        log(Severity.INFO, "Monitor", "Monitoring stopped")
        changed()
    }

    private suspend fun probe(t: Target): Float {
        val addr = resolve(t) ?: return Float.NaN
        return withContext(Dispatchers.IO) {
            when (t.kind) {
                ProbeKind.ICMP -> pinger.ping(addr, timeoutMs).let {
                    if (it.status == PingStatus.OK) it.rttMs.toFloat() else Float.NaN
                }
                ProbeKind.DNS -> DnsProbe.query(addr, t.dnsQuery, timeoutMs.coerceAtLeast(1000)).let {
                    if (it.ok) it.rttMs.toFloat() else Float.NaN
                }
            }
        }
    }

    private sealed interface Signal {
        data object OutageStart : Signal
        data class Recovered(val seconds: Double, val lost: Int) : Signal
        data class Spike(val rtt: Double, val normal: Double) : Signal
    }

    /** Updates a target's state with a new sample and reports anything noteworthy. */
    private fun record(t: Target, s: Sample): Signal? {
        t.add(s)
        if (s.lost) {
            t.consecutiveLost++
            if (t.consecutiveLost == OUTAGE_THRESHOLD) {
                t.outageStart = s.time - (OUTAGE_THRESHOLD - 1) * intervalMs.toLong()
                return Signal.OutageStart
            }
            return null
        }
        var signal: Signal? = t.outageStart?.let { start -> Signal.Recovered((s.time - start) / 1000.0, t.consecutiveLost) }
        t.outageStart = null
        t.consecutiveLost = 0

        val rtt = s.rtt.toDouble()
        val base = t.ema
        if (!base.isNaN()) {
            val minJump = if (t.role == TargetRole.GATEWAY) 25.0 else 60.0
            if (!t.inSpike && rtt > base * 3 && rtt - base > minJump) {
                t.inSpike = true
                if (signal == null) signal = Signal.Spike(rtt, base)
            } else if (t.inSpike && rtt < base * 1.5) {
                t.inSpike = false
            }
        }
        // Spikes shouldn't drag the baseline up too quickly.
        val alpha = if (t.inSpike) 0.02 else 0.1
        t.ema = if (base.isNaN()) rtt else base + alpha * (rtt - base)
        return signal
    }

    /**
     * Logs one event per kind per round. Because every target is probed at the same moment, the
     * earliest point in the path that is affected tells us where the problem starts.
     */
    private fun logRound(signals: List<Pair<Target, Signal>>) {
        fun origin(ts: List<Target>): String {
            val roles = ts.map { it.role }.toSet()
            return when {
                TargetRole.GATEWAY in roles -> "starts at your router → local link (PC ↔ router) or the router itself"
                TargetRole.ISP in roles -> "starts at the ISP edge → beyond your router (modem / ISP line)"
                TargetRole.INTERNET in roles && ts.size > 1 -> "router and ISP edge fine → upstream / Internet"
                TargetRole.INTERNET in roles -> "one Internet anchor only → that host's path"
                roles == setOf(TargetRole.DNS) -> "DNS server only"
                else -> "remote host only; your connection was fine"
            }
        }
        fun names(ts: List<Target>) = ts.joinToString(", ") { it.name }

        val outages = signals.filter { it.second is Signal.OutageStart }.map { it.first }.sortedBy { it.role.order }
        if (outages.isNotEmpty()) {
            val src = outages.first()
            val msg = if (outages.size == 1) {
                val what = if (src.kind == ProbeKind.DNS) "DNS queries failing" else "No response"
                "$what from ${src.name} (${src.displayAddress})"
            } else "No response from ${names(outages)}"
            log(Severity.ERROR, src.role.label, "$msg — ${origin(outages)}")
        }

        val recovered = signals.filter { it.second is Signal.Recovered }.sortedBy { it.first.role.order }
        if (recovered.isNotEmpty()) {
            val (src, sig) = recovered.first()
            val r = sig as Signal.Recovered
            val who = if (recovered.size == 1) "${src.name} (${src.displayAddress})" else names(recovered.map { it.first })
            log(Severity.SUCCESS, src.role.label, "%s responding again after %.0f s outage (%d probes lost)".format(who, r.seconds, r.lost))
        }

        val spikes = signals.filter { it.second is Signal.Spike }.sortedBy { it.first.role.order }
        if (spikes.isNotEmpty()) {
            val detail = spikes.joinToString(", ") { (t, sig) ->
                val sp = sig as Signal.Spike
                "%s %.0f ms (normal ~%.0f)".format(t.name, sp.rtt, sp.normal)
            }
            log(Severity.WARNING, spikes.first().first.role.label, "Latency spike: $detail — ${origin(spikes.map { it.first })}")
        }
    }

    fun clearData() {
        targets.forEach {
            it.samples.clear(); it.consecutiveLost = 0; it.outageStart = null; it.inSpike = false; it.ema = Double.NaN
        }
        wifiHistory.clear()
        if (running) startedAt = System.currentTimeMillis()
        tickListeners.forEach { it() }
        changed()
    }

    companion object {
        const val OUTAGE_THRESHOLD = 3
    }
}
